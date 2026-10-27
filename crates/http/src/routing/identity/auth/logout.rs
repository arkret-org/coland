use arkret_models_collaboration::session_grants::AuthenticationSessionTerminationResponseBody;

use super::*;

/// `POST /_arkret/gate/account/logout` — spec `ak.gate.account.command.logout.v1`,
/// the single client-visible hard logout (account-lifecycle §4.1).
///
/// Request identity differs from every other protected endpoint: per §4.1 the
/// caller presents `Authorization: DPoP <ak.session.grant>` (NOT the coland
/// principal bearer) plus a `DPoP` holder proof bound to the grant's `cnf.jkt`.
/// We therefore do NOT run the coland session-bearer pipeline
/// (`AuthArgs::authenticated_session`) here; instead we identify the
/// principal/device from the presented grant via coauth server-to-server
/// introspection.
///
/// Termination is two-sided and ordered:
///  - **Auth-side (first):** call the Account Authority process S2S `auth-sessions/logout`
///    sub-operation so the grant rotation chain + browser session are terminated (§4.1 step 2).
///  - **Principal-side (after Auth-side success):** revoke the principal's local bearer sessions
///    for the grant's device, remove push registrations, and drop queued to-device messages. It
///    does NOT issue an AccountStatusRecord, emit `ak.device.revoke`, or mark the durable device
///    inventory record revoked; a later login restores a session for the same authorized device.
#[salvo::oapi::endpoint(operation_id = "ak.gate.account.command.logout", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.gate.account.command.logout.v1"))]
pub(super) async fn logout(
    aa: super::super::AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountLogoutResponseBody> {
    let _ = &aa; // header presence registered with the OpenAPI doc
    let state = depot.get_typed::<AppState>().expect("state injected");

    // Development fallback: with no Account Authority process introspection wired (dev mode
    // dev-login mints plain coland bearers, not DPoP-bound grants), treat the
    // Authorization bearer as a local session bearer and perform the
    // principal-side termination directly. Production keeps the strict
    // grant+DPoP+introspection contract below.
    #[cfg(any(test, feature = "conformance-harness"))]
    if state.config().development_harness_enabled() && state.local_account_authority().is_none() {
        let grant_jwt = bearer_token(req)
            .map(str::to_owned)
            .ok_or_else(|| AppError::unauthenticated("missing local development bearer"))?;
        require_logout_body(req).await?;
        return json_ok(dev_mode_local_logout(state, &grant_jwt).await?);
    }

    // §4.1 — identify the DPoP-scheme grant's subject + device by
    // introspecting it against the Account Authority process over the existing S2S channel.
    let grant_jwt = dpop_token(req)
        .map(str::to_owned)
        .ok_or_else(|| AppError::unauthenticated("missing DPoP session grant"))?;

    let grant = introspect_session_grant_for_logout(state, &grant_jwt).await?;
    // The public Account Authority base is the sole client-visible origin for
    // every `gate/account` operation. A deployment gateway may route this
    // exact operation to the Principal service for its local cleanup step,
    // but the holder proof remains bound to that advertised external origin.
    let logout_public_base = state
        .config()
        .account_authority_url
        .as_deref()
        .unwrap_or(&state.config().public_base_url);
    let digest = session_credential_hash(&grant_jwt, state.service_id());
    let (record, reserve) = if let Some(grant) = grant {
        if grant.credential_class
            != arkret_models_identity::session_credential::SessionGrantCredentialClass::Standard
            || !matches!(
                &grant.holder_binding,
                arkret_models_identity::SessionGrantHolderBinding::HumanDevice { .. }
            )
            || !grant
                .revocation_ref
                .starts_with("org.arkret.coauth.browser_session:")
            || grant.revocation_ref == "org.arkret.coauth.browser_session:"
        {
            return Err(AppError::unauthenticated(
                "account logout requires a browser-bound standard human grant",
            ));
        }
        super::super::auth_grant_dpop::verify_grant_dpop_request_at_base(
            req,
            &grant_jwt,
            Some(&grant.cnf_jkt),
            logout_public_base,
        )
        .map_err(auth_error_to_app_error)?;
        let session =
            super::super::auth_grant_dpop::session_record_from_introspected_grant_for_logout(
                state, &grant_jwt, &grant,
            )
            .map_err(auth_error_to_app_error)?;
        if session.agent_session().is_some() {
            return Err(AppError::unauthenticated(
                "account logout requires a device-bound session grant",
            ));
        }
        let record = coland_storage::PushHardLogoutJournalRecord {
            grant_token_digest: digest.clone(),
            revocation_ref: grant.revocation_ref,
            account_id: grant.account_id,
            device_id: arkret_wire::DeviceId::new(session.require_human_device_id())
                .map_err(|error| AppError::internal(error.to_string()))?,
            cnf_jkt: grant.cnf_jkt,
            auth_side_confirmed: false,
            completed_at: None,
            created_at: now(),
        };
        (record, true)
    } else {
        let record = state
            .persistence()
            .push_hard_logout_journal(&digest)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(|| {
                AppError::unauthenticated("session grant logout has no verifiable holder metadata")
            })?;
        super::super::auth_grant_dpop::verify_grant_dpop_request_at_base(
            req,
            &grant_jwt,
            Some(&record.cnf_jkt),
            logout_public_base,
        )
        .map_err(auth_error_to_app_error)?;
        (record, false)
    };
    require_logout_body(req).await?;
    let journal = if reserve {
        state
            .persistence()
            .reserve_push_hard_logout_journal(&record)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
    } else {
        record
    };
    if journal.completed_at.is_some() {
        return json_ok(AccountLogoutResponseBody { revoked: false });
    }

    if !journal.auth_side_confirmed {
        trigger_auth_side_auth_session_logout(state, &grant_jwt).await?;
        state
            .persistence()
            .mark_push_hard_logout_auth_confirmed(&digest)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?;
    }

    // §4.1 step 3 (Principal-side, local): invalidate this grant's cached
    // introspection so the next `/_arkret/self/*` request re-introspects against
    // coauth and observes `active=false` once the Auth-side chain is terminated
    // below. There is NO local bearer to revoke (② removed the exchange); the
    // local session revoke + push-route cleanup + this cache invalidation together
    // fail-close the device's subsequent requests without revoking its durable
    // Event-signing authorization.
    super::super::auth_grant_dpop::invalidate_cached_grant(state, &grant_jwt);

    let actor = journal.account_id.principal_id.as_str();
    let device_id = journal.device_id.as_str();
    let revoked_count = revoke_sessions_for_actor_device(state, actor, device_id).await?;
    crate::routing::interop::unregister_public_push_for_hard_logout(
        state,
        &journal.account_id,
        &journal.device_id,
    )
    .await?;
    let delivery_purge = state
        .deliveries()
        .purge_device_delivery(actor, device_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    state
        .persistence()
        .mark_push_hard_logout_completed(&digest, now())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    // The durable journal and the verified DPoP holder bind this completion
    // to the exact principal/device even when introspection now says NotFound.
    // In the direct session-grant model there is no second Principal-local
    // bearer row, so `revoked_count == 0` does not undo the logical logout.
    let revoked = true;
    append_audit_log(
        state,
        Some(actor),
        "auth.logout",
        json!({
            "device_id": device_id,
            "principal_side_sessions_revoked": revoked_count,
            "to_device_messages_dropped": delivery_purge.to_device_messages_dropped,
            "push_registrations_removed": delivery_purge.push_registrations_removed,
        }),
        "accepted",
    )
    .await;

    json_ok(AccountLogoutResponseBody { revoked })
}

async fn require_logout_body(req: &mut Request) -> Result<(), AppError> {
    let value = req
        .parse_json::<serde_json::Value>()
        .await
        .map_err(|_| AppError::json_invalid("logout requires a JSON request body"))?;
    serde_json::from_value::<arkret_models_identity::AccountLogoutRequestBody>(value)
        .map_err(|_| AppError::schema_violation("logout requires a closed empty request body"))?;
    Ok(())
}

fn auth_error_to_app_error(error: (StatusCode, &'static str, &'static str)) -> AppError {
    let (status, code, message) = error;
    if let Some(error_code) = ErrorCode::from_wire(code) {
        return AppError::from_rejection(error_code, message);
    }
    match status {
        StatusCode::SERVICE_UNAVAILABLE => {
            crate::app_error!(TemporarilyUnavailable, message)
        }
        StatusCode::INTERNAL_SERVER_ERROR => AppError::internal(message),
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            AppError::param_invalid(message)
        }
        _ => AppError::unauthenticated(message),
    }
}

/// Development-mode hard logout: with no Account Authority process introspection wired,
/// `dev_login` mints plain coland session bearers (not DPoP-bound grants), so
/// the Authorization bearer IS the local session bearer. Perform the
/// principal-side termination directly (revoke the bearer session + remove
/// push registrations), mirroring the production
/// principal-side effects without an Account Authority process round-trip. The durable
/// device authorization remains active across logout and re-login.
#[cfg(any(test, feature = "conformance-harness"))]
async fn dev_mode_local_logout(
    state: &AppState,
    token: &str,
) -> Result<AccountLogoutResponseBody, AppError> {
    let token_hash = session_credential_hash(token, state.service_id());
    let revoked_session = state
        .sessions()
        .revoke_session(&token_hash, now())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let revoked = revoked_session.is_some();
    if let Some(session) = revoked_session {
        let delivery_purge =
            purge_device_delivery_state(state, &session.actor, session.require_human_device_id())
                .await;
        append_audit_log(
            state,
            Some(&session.actor),
            "auth.logout",
            json!({
                "device_id": session.require_human_device_id(),
                "revoked_at": session.revoked_at,
                "to_device_messages_dropped": delivery_purge.to_device_messages_dropped,
                "push_registrations_removed": delivery_purge.push_registrations_removed,
            }),
            "accepted",
        )
        .await;
    }
    Ok(AccountLogoutResponseBody { revoked })
}

/// Server-to-server introspection of a presented `ak.session.grant` for the
/// logout path. Unlike ordinary protected requests, hard logout is authorized
/// by the DPoP holder proof on the logout request itself, so this read only
/// obtains grant metadata needed for local DPoP validation and Principal-side
/// cleanup.
async fn introspect_session_grant_for_logout(
    state: &AppState,
    grant_jwt: &str,
) -> Result<Option<crate::wire::SessionGrantValidationMetadata>, AppError> {
    let response =
        super::super::account_authority_client::AccountAuthorityClient::from_state(state)?
            .introspect_logout_grant(grant_jwt)
            .await?;
    classify_logout_introspection(response)
}

/// A metadata-free `not_found` may continue only through an exact durable
/// journal binding whose DPoP holder is still verified by the caller.
fn classify_logout_introspection(
    outcome: crate::wire::SessionGrantValidationResponseBody,
) -> Result<Option<crate::wire::SessionGrantValidationMetadata>, AppError> {
    use crate::wire::SessionGrantAdminIntrospectionStatus;

    match outcome.status {
        SessionGrantAdminIntrospectionStatus::NotFound
            if !outcome.active && outcome.grant.is_none() =>
        {
            Ok(None)
        }
        SessionGrantAdminIntrospectionStatus::AudienceMismatch => Err(AppError::unauthenticated(
            "session grant audience does not match this Account Authority",
        )),
        SessionGrantAdminIntrospectionStatus::Active if outcome.active => outcome
            .grant
            .map(Some)
            .ok_or_else(|| invalid_logout_introspection(outcome.status)),
        SessionGrantAdminIntrospectionStatus::Active
        | SessionGrantAdminIntrospectionStatus::NotFound => {
            Err(invalid_logout_introspection(outcome.status))
        }
        status if !outcome.active => outcome
            .grant
            .map(Some)
            .ok_or_else(|| invalid_logout_introspection(status)),
        status => Err(invalid_logout_introspection(status)),
    }
}

fn invalid_logout_introspection(
    status: crate::wire::SessionGrantAdminIntrospectionStatus,
) -> AppError {
    crate::app_error!(
        TemporarilyUnavailable,
        format!("invalid session grant logout introspection outcome for status {status:?}"),
    )
}

/// Auth-side trigger of the single hard logout: call the Account Authority process's S2S
/// `POST {gate_account_base_url}/auth-sessions/logout` sub-operation so the grant
/// rotation chain + browser session are terminated (account-lifecycle §4.1
/// step 2). When introspection returned grant metadata, the client DPoP proof
/// is validated by coland before this call and is not forwarded to the Auth
/// Server. A `not_found` retry has no holder metadata left to validate; this
/// sub-operation then only confirms that no Auth-side chain remains.
async fn trigger_auth_side_auth_session_logout(
    state: &AppState,
    grant_jwt: &str,
) -> Result<(), AppError> {
    let body = super::super::account_authority_client::AccountAuthorityClient::from_state(state)?
        .logout_auth_session(grant_jwt, now())
        .await?;
    confirm_auth_side_logout(body)
}

fn confirm_auth_side_logout(
    body: AuthenticationSessionTerminationResponseBody,
) -> Result<(), AppError> {
    if body.grant_chain_terminated && body.authentication_session_logged_out {
        return Ok(());
    }
    Err(crate::app_error!(
        TemporarilyUnavailable,
        "Auth-side session logout did not confirm grant-chain termination",
    ))
}

/// Revoke every active coland bearer session for a specific (actor, device).
/// Used by the single hard logout so only the logging-out device's local
/// sessions are terminated (other devices stay logged in).
pub(crate) async fn revoke_sessions_for_actor_device(
    state: &AppState,
    actor: &str,
    device_id: &str,
) -> Result<usize, AppError> {
    let revoked_at = now();
    state
        .sessions()
        .revoke_actor_device_sessions(actor, device_id, revoked_at)
        .await
        .map_err(|error| AppError::internal(error.to_string()))
}

#[cfg(test)]
mod logout_introspection_tests {
    use super::*;
    use crate::wire::SessionGrantAdminIntrospectionStatus;

    fn outcome(
        active: bool,
        status: SessionGrantAdminIntrospectionStatus,
    ) -> crate::wire::SessionGrantValidationResponseBody {
        crate::wire::SessionGrantValidationResponseBody {
            active,
            status,
            proof_required: false,
            one_time_use_consumed: false,
            grant: None,
        }
    }

    #[test]
    fn not_found_requires_an_exact_journal_before_handler_can_continue() {
        assert!(matches!(
            classify_logout_introspection(outcome(
                false,
                SessionGrantAdminIntrospectionStatus::NotFound,
            )),
            Ok(None)
        ));
    }

    #[test]
    fn not_found_retry_requires_holder_proof_bound_to_saved_jkt() {
        let request = Request::default();
        let error = super::super::super::auth_grant_dpop::verify_grant_dpop_request_at_base(
            &request,
            "presented-grant",
            Some("saved-journal-jkt"),
            "https://account.example",
        )
        .expect_err("a metadata-free retry cannot pass without its holder proof");
        assert_eq!(error.1, "unauthenticated");
    }

    #[test]
    fn audience_mismatch_remains_fail_closed() {
        let error = classify_logout_introspection(outcome(
            false,
            SessionGrantAdminIntrospectionStatus::AudienceMismatch,
        ))
        .expect_err("audience mismatch must be rejected");
        assert_eq!(error.code, ErrorCode::Unauthenticated);
    }

    #[test]
    fn missing_metadata_for_other_statuses_is_a_protocol_failure() {
        for status in [
            SessionGrantAdminIntrospectionStatus::Active,
            SessionGrantAdminIntrospectionStatus::Revoked,
            SessionGrantAdminIntrospectionStatus::Expired,
        ] {
            let error = classify_logout_introspection(outcome(
                status == SessionGrantAdminIntrospectionStatus::Active,
                status,
            ))
            .expect_err("non-not-found outcome must carry grant metadata");
            assert_eq!(error.code, ErrorCode::TemporarilyUnavailable);
        }
    }

    #[test]
    fn auth_side_must_confirm_both_terminal_states() {
        assert!(
            confirm_auth_side_logout(AuthenticationSessionTerminationResponseBody {
                grant_chain_terminated: true,
                authentication_session_logged_out: true,
            })
            .is_ok()
        );

        for body in [
            AuthenticationSessionTerminationResponseBody {
                grant_chain_terminated: false,
                authentication_session_logged_out: true,
            },
            AuthenticationSessionTerminationResponseBody {
                grant_chain_terminated: true,
                authentication_session_logged_out: false,
            },
            AuthenticationSessionTerminationResponseBody {
                grant_chain_terminated: false,
                authentication_session_logged_out: false,
            },
        ] {
            let error = confirm_auth_side_logout(body)
                .expect_err("partial Auth-side completion must be retryable");
            assert_eq!(error.code, ErrorCode::TemporarilyUnavailable);
        }
    }
}
