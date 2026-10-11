use arkret_wire::{
    AuthorityCommitStatus, AuthorityRejectionStatus, AuthoritySubmitOutcome,
    AuthoritySubmitRequest, EventAdmissionSubmission,
};
use coland_http::error::AppError;
use coland_http::result::{JsonResult, json_ok};
use coland_services::ServiceErrorKind;
use coland_services::authority_commit::AuthorityEventAdmissionOutcome;
use salvo::prelude::*;

use crate::state::AppState;

/// The configured Account Authority reads its own Station's controller state
/// at issuance/refresh. This is not the controller-only public GET surface.
#[handler]
pub(super) async fn read_agent_participation(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<
    arkret_models_collaboration::governance::agent_participation::AgentParticipationOutcome,
> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::peer::authenticate_account_authority_private_request(state, req)?;
    let (agent, controller) = req
        .parse_json::<(arkret_wire::AccountId, arkret_wire::AccountId)>()
        .await
        .map_err(|_| AppError::json_invalid("invalid private Agent/controller Account binding"))?;
    if agent.station_id != state.service_core_id() || controller.station_id != agent.station_id {
        return Err(crate::app_error!(
            CapabilityDenied,
            "private participation read belongs to another Station",
        ));
    }
    let record = state
        .agent_pairings()
        .agent(agent.principal_id.as_str())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| {
            crate::app_error!(CapabilityDenied, "Agent controller binding is unavailable",)
        })?;
    if record.controller_principal_id != controller.principal_id.as_str()
        || crate::routing::identity::agent_pcr::agent_controller_account(state, &record).await?
            != controller
    {
        return Err(crate::app_error!(
            CapabilityDenied,
            "private participation read names another controller Account",
        ));
    }
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await?;
    json_ok(
        crate::routing::identity::agents::load_agent_participation_outcome(
            state,
            agent.principal_id.as_str(),
        )
        .await?,
    )
}

/// Admit the `accepted_device` `ak.device.authorize` Event a device pairing
/// finalize hands over from this deployment's Account Authority.
///
/// Device pairing is the only flow the Account Authority completes through
/// this Station's authority log (device-lifecycle.md §5.4). Every other Event
/// kind has its own registered admission unit with its own domain
/// authorization, so this private edge refuses it before any storage access
/// instead of committing it without that authorization.
#[handler]
#[tracing::instrument(skip_all, fields(op = "coland.account_authority.events.admit"))]
pub(super) async fn admit_event(
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AuthoritySubmitOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    super::peer::authenticate_account_authority_private_request(state, req)?;

    let submission = req
        .parse_json::<EventAdmissionSubmission>()
        .await
        .map_err(|_| AppError::json_invalid("invalid private Event admission body"))?;
    submission
        .validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if submission.event.kind != arkret_wire::EventKind::DeviceAuthorize {
        return Err(crate::app_error!(
            UnsupportedEventKind,
            "the Account Authority private admission accepts only ak.device.authorize",
        ));
    }
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::param_invalid("Idempotency-Key is required"))?;
    if idempotency_key != submission.event.event_id.as_str() {
        return Err(AppError::conflict(
            "Idempotency-Key must equal the submitted event_id",
        ));
    }

    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(AppError::internal)?;
    let outcome = accepted_device_outcome(
        state
            .authority_commits()
            .admit_accepted_device_authorization(
                &submission.event,
                &state.service_core_id(),
                verification_method,
                state.notary_signing_key().as_ref(),
                chrono::Utc::now(),
            )
            .await,
    );
    outcome
        .validate_for_request(&AuthoritySubmitRequest::Event(submission))
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}

/// The Account Authority abandons a frozen pairing admission only on a
/// terminal `rejected` outcome, so every refusal the accepted-device unit
/// decides from durable PCR state or from the Event itself is terminal and
/// carries its registered reason; a lost head race or an unavailable store is
/// retryable and leaves the reservation in place.
fn accepted_device_outcome(
    admission: coland_services::ServiceResult<AuthorityEventAdmissionOutcome>,
) -> AuthoritySubmitOutcome {
    use coland_storage::ConflictCode;

    let rejected = |reason_code: &str| AuthoritySubmitOutcome::Rejected {
        status: AuthorityRejectionStatus::Rejected,
        reason_code: reason_code.to_owned(),
    };
    let retryable = || AuthoritySubmitOutcome::Rejected {
        status: AuthorityRejectionStatus::RetryableUnavailable,
        reason_code: "authority_transaction_unavailable".to_owned(),
    };
    match admission {
        Ok(AuthorityEventAdmissionOutcome::Committed(commit)) => AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit,
        },
        Ok(AuthorityEventAdmissionOutcome::Duplicate(commit)) => AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Duplicate,
            commit,
        },
        Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority) => rejected("authority_mismatch"),
        Err(error) => match error.kind() {
            ServiceErrorKind::SchemaViolation => rejected(ConflictCode::SchemaViolation.as_str()),
            ServiceErrorKind::Conflict => match error.conflict_code() {
                Some(
                    code @ (ConflictCode::DeviceRevoked
                    | ConflictCode::DeviceRevocationPending
                    | ConflictCode::DeviceGenerationFenced
                    | ConflictCode::DeviceUnauthorized
                    | ConflictCode::SignatureInvalid
                    | ConflictCode::SchemaViolation
                    | ConflictCode::EventIdDigestMismatch
                    | ConflictCode::DuplicateConflict
                    | ConflictCode::FailedPrecondition),
                ) => rejected(code.as_str()),
                _ => {
                    tracing::warn!(error = %error, "accepted-device admission lost its PCR cut");
                    retryable()
                }
            },
            ServiceErrorKind::UnsupportedEventKind
            | ServiceErrorKind::NotFound
            | ServiceErrorKind::Database
            | ServiceErrorKind::Internal => {
                tracing::warn!(error = %error, "accepted-device admission unavailable");
                retryable()
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use coland_storage::ConflictCode;

    use super::*;

    fn conflict(
        code: ConflictCode,
    ) -> coland_services::ServiceResult<AuthorityEventAdmissionOutcome> {
        Err(coland_services::ServiceError::Conflict(format!(
            "{code}: diagnostic"
        )))
    }

    #[test]
    fn accepted_device_refusals_are_terminal_and_races_are_retryable() {
        for code in [
            ConflictCode::DeviceRevoked,
            ConflictCode::DeviceRevocationPending,
            ConflictCode::DeviceGenerationFenced,
            ConflictCode::SignatureInvalid,
            ConflictCode::DuplicateConflict,
        ] {
            assert_eq!(
                accepted_device_outcome(conflict(code)),
                AuthoritySubmitOutcome::Rejected {
                    status: AuthorityRejectionStatus::Rejected,
                    reason_code: code.as_str().to_owned(),
                }
            );
        }
        for retryable in [
            conflict(ConflictCode::CasConflict),
            Err(coland_services::ServiceError::Database("down".to_owned())),
        ] {
            assert!(matches!(
                accepted_device_outcome(retryable),
                AuthoritySubmitOutcome::Rejected {
                    status: AuthorityRejectionStatus::RetryableUnavailable,
                    ..
                }
            ));
        }
        assert_eq!(
            accepted_device_outcome(Ok(AuthorityEventAdmissionOutcome::NotCurrentAuthority)),
            AuthoritySubmitOutcome::Rejected {
                status: AuthorityRejectionStatus::Rejected,
                reason_code: "authority_mismatch".to_owned(),
            }
        );
    }

    #[test]
    fn private_adapter_is_not_a_protocol_operation() {
        let source = include_str!("account_authority_private.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert!(!source.contains("oapi::endpoint"));
        assert!(!source.contains("Arkret-Operation"));
        assert!(source.contains(".admit_accepted_device_authorization("));
        assert!(source.contains("authority_transaction_unavailable"));
        assert!(!source.contains(".admit_event("));
    }

    const CREDENTIAL: &str = "shared-internal-channel-credential";

    fn private_channel_state() -> AppState {
        let values = std::collections::BTreeMap::from([
            (
                "COLAND_TRUST_DOMAIN".to_owned(),
                "ak:trust_domain:coland.example".to_owned(),
            ),
            ("COLAND_DEVELOPMENT_MODE".to_owned(), "true".to_owned()),
            (
                "COLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
                "https://auth.coland.example".to_owned(),
            ),
            (
                "COLAND_INTERNAL_AUTHORITY_SHARED_SECRET".to_owned(),
                CREDENTIAL.to_owned(),
            ),
            (
                "COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN".to_owned(),
                "ak:trust_domain:auth.coland.example".to_owned(),
            ),
        ]);
        let mut config = crate::config::AppConfig::from_values(
            &values,
            crate::config::StartupOverrides::default(),
        )
        .unwrap();
        config.seed_demo_data = false;
        AppState::new(config, coland_storage_postgres::Db { pool: None })
    }

    fn submission(
        kind: arkret_wire::EventKind,
        payload: serde_json::Value,
    ) -> EventAdmissionSubmission {
        let actor = crate::test_actor_id_str("did:web:private-admission.example");
        let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            arkret_canonical::sha256_bytes(b"private-admission-realm"),
        ));
        let mut event = crate::test_event::raw_event(
            kind.as_str(),
            arkret_wire::ScopeRef::Realm { realm_id },
            actor,
            0,
            arkret_identifiers::Hlc::new("019041000000-0000-aabbccdd").unwrap(),
            payload,
        )
        .unwrap();
        crate::test_event::attach_structural_only_producer_proof(
            &mut event,
            arkret_wire::DidUrl::new("did:web:private-admission.example#key").unwrap(),
        );
        EventAdmissionSubmission::new(event)
    }

    #[tokio::test]
    async fn agent_participation_private_read_rejects_missing_credentials_and_foreign_accounts() {
        let state = private_channel_state();
        let router = salvo::Router::new()
            .hoop(salvo::affix_state::inject(state.clone()))
            .push(crate::routing::events::account_authority_private_router());
        let service = salvo::Service::new(router);
        let principal =
            arkret_wire::DidCoreId::new("ak:did_core:web:private-agent.example").unwrap();
        let controller =
            arkret_wire::DidCoreId::new("ak:did_core:web:private-controller.example").unwrap();
        let local = (
            arkret_wire::AccountId::new(principal.clone(), state.service_core_id()),
            arkret_wire::AccountId::new(controller.clone(), state.service_core_id()),
        );
        let response = salvo::test::TestClient::post(
            "http://server/account-authority/agent-participation/read",
        )
        .json(&local)
        .send(&service)
        .await;
        assert!(matches!(
            response.status_code,
            Some(salvo::http::StatusCode::UNAUTHORIZED | salvo::http::StatusCode::FORBIDDEN)
        ));
        let foreign =
            arkret_wire::DidCoreId::new("ak:did_core:web:foreign-station.example").unwrap();
        for accounts in [
            (
                arkret_wire::AccountId::new(principal, foreign.clone()),
                local.1.clone(),
            ),
            (
                local.0.clone(),
                arkret_wire::AccountId::new(controller, foreign),
            ),
        ] {
            let response = salvo::test::TestClient::post(
                "http://server/account-authority/agent-participation/read",
            )
            .add_header("authorization", format!("Bearer {CREDENTIAL}"), true)
            .json(&accounts)
            .send(&service)
            .await;
            assert_eq!(
                response.status_code,
                Some(salvo::http::StatusCode::FORBIDDEN)
            );
        }
    }

    /// Only the `accepted_device` unit may be reached through the Account
    /// Authority's private channel. Any other kind is refused with
    /// `unsupported_event_kind` before storage, so nothing is queued or
    /// committed and no current result is written.
    #[tokio::test]
    async fn private_admission_refuses_every_kind_but_device_authorize_with_zero_writes() {
        use salvo::test::ResponseExt as _;

        let state = private_channel_state();
        let router = salvo::Router::new()
            .hoop(salvo::affix_state::inject(state.clone()))
            .push(crate::routing::events::account_authority_private_router());
        let service = salvo::Service::new(router);
        for (kind, payload) in [
            (
                arkret_wire::EventKind::MemberState,
                serde_json::json!({"membership": "join"}),
            ),
            (
                arkret_wire::EventKind::CapabilityGrant,
                serde_json::json!({}),
            ),
            (
                arkret_wire::EventKind::AgentKeyAuthorize,
                serde_json::json!({}),
            ),
            (arkret_wire::EventKind::MessageCreate, serde_json::json!({})),
        ] {
            let submission = submission(kind.clone(), payload);
            let event_id = submission.event.event_id.clone();
            let mut response =
                salvo::test::TestClient::post("http://server/account-authority/events/admit")
                    .add_header("authorization", format!("Bearer {CREDENTIAL}"), true)
                    .add_header("idempotency-key", event_id.as_str(), true)
                    .json(&submission)
                    .send(&service)
                    .await;
            assert_eq!(
                response.status_code,
                Some(salvo::http::StatusCode::NOT_IMPLEMENTED),
                "{kind:?} must fail closed"
            );
            let body: serde_json::Value = response.take_json().await.unwrap();
            assert_eq!(
                body["type"], "https://arkret.org/problems/unsupported_event_kind",
                "{kind:?}: {body}"
            );
            assert!(
                state
                    .authority_commits()
                    .queued_event(&event_id)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}
