//! Canonical current-protocol authority routes.
//!
//! `POST /_arkret/self/events` is mounted by the events router; this module
//! contributes the self and peer stream scans and the open authority bundle.
//! Planned handoff installs only a complete, verified frozen migration cut.

use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody;
use arkret_wire::{ErrorCode, RealmAuthorityBundleRequestBody, StreamScanRequestBody};
use coland_services::{ServiceError, ServiceResult};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Serialize;

use crate::state::AppState;

#[cfg(feature = "conformance-harness")]
pub(crate) fn trace_submission_refusal(
    stage: &'static str,
    kind_class: &'static str,
    actor_class: &'static str,
    error: Option<&ServiceError>,
) {
    let code = error.and_then(ServiceError::conflict_code);
    let wire_code = code
        .and_then(|code| ErrorCode::from_wire(code.as_str()))
        .map(|code| code.as_str())
        .unwrap_or("unregistered");
    let reason_code = code
        .map(|code| code.as_str())
        .filter(|code| arkret_wire::ReasonCode::is_registered(code))
        .unwrap_or("unregistered");
    // Local conformance diagnostics disclose only fixed implementation
    // conditions, never request material or controller-private bindings.
    let local_condition = match error {
        Some(ServiceError::Conflict(detail)) => detail
            .strip_prefix("failed_precondition: ")
            .filter(|condition| {
                matches!(
                    *condition,
                    "Agent join lacks its controller binding"
                        | "controller is not in its bound joined generation"
                        | "Agent has no accepted provision"
                        | "Agent lifecycle is not active"
                        | "Agent accountability grant is not active"
                        | "Agent complete accepted ownership and DID binding are unavailable"
                        | "Agent has no claimable membership KeyPackage"
                        | "Agent accepted PCR genesis is unavailable"
                        | "Agent accepted genesis inception is unavailable"
                        | "Agent complete native DID history is unavailable"
                )
            })
            .unwrap_or("other"),
        _ => "other",
    };
    tracing::warn!(
        stage,
        kind_class,
        actor_class,
        wire_code,
        reason_code,
        local_condition,
        "self submission refusal boundary"
    );
}

#[cfg(feature = "conformance-harness")]
pub(crate) fn submission_kind_class(kind: &arkret_wire::EventKind) -> &'static str {
    match kind {
        arkret_wire::EventKind::KeyBackupActiveSeries => "key_backup_pointer",
        arkret_wire::EventKind::MlsGenesis | arkret_wire::EventKind::MlsCommit => "mls",
        _ => "ordinary_event",
    }
}

#[cfg(feature = "conformance-harness")]
fn trace_stream_read_refusal(
    stage: &'static str,
    stream_class: &'static str,
    code: Option<ErrorCode>,
) {
    tracing::warn!(
        stage,
        stream_class,
        wire_code = code.map(ErrorCode::as_str).unwrap_or("unregistered"),
        "self stream read refusal boundary"
    );
}

#[cfg(feature = "conformance-harness")]
fn diagnostic_stream_class(request: &StreamScanRequestBody) -> &'static str {
    match request.stream_ref {
        arkret_wire::CommitStreamRef::Realm { .. } => "realm",
        arkret_wire::CommitStreamRef::Circle { .. } => "circle",
        arkret_wire::CommitStreamRef::Sidecar { .. } => "sidecar",
        _ => "other",
    }
}

/// `ak.self.committed_event.read.scan.v1`, under the authenticated `self` tree.
pub(super) fn self_router() -> Router {
    Router::with_path("streams/scan").post(scan_stream)
}

/// `ak.peer.committed_event.read.scan.v1`, under the signed `peer` tree.
pub(super) fn peer_router() -> Router {
    Router::new()
        .push(
            Router::with_path("realm-actors/material")
                .post(super::identity::realm_actor_account_material::peer_read),
        )
        .push(Router::with_path("streams/scan").post(peer_scan_stream))
        .push(Router::with_path("realm-authority/handoff").post(peer_handoff))
        .push(
            Router::with_path("strands/watch/current")
                .post(super::self_current_reads::peer_strand_watch_current),
        )
        .push(
            Router::with_path("strands/watch/audit-read")
                .post(super::self_current_reads::peer_strand_watch_audit_read),
        )
}

/// `ak.open.realm_authority.read.bundle.v1`, under the unauthenticated `open` tree.
pub(super) fn open_router() -> Router {
    Router::with_path("realm-authority/bundle").post(authority_bundle)
}

/// Responses carrying authorization results, authority bundles, or Commits
/// are never cacheable (`service-http-binding.md` §6).
pub(super) fn no_store(res: &mut Response) {
    res.headers_mut().insert(
        salvo::http::header::CACHE_CONTROL,
        salvo::http::HeaderValue::from_static("no-store"),
    );
}

/// Decode the exact body as the closed request type: malformed JSON is
/// `json_invalid`, a well-formed body outside the schema `schema_violation`.
pub(super) async fn parse_closed_body<T: serde::de::DeserializeOwned>(
    req: &mut Request,
    res: &mut Response,
) -> Option<T> {
    parse_exact_closed_body(req, res)
        .await
        .map(|(value, _)| value)
}

/// [`parse_closed_body`] that also returns the exact request bytes.
async fn parse_exact_closed_body<T: serde::de::DeserializeOwned>(
    req: &mut Request,
    res: &mut Response,
) -> Option<(T, Vec<u8>)> {
    let body = match req.payload().await {
        Ok(body) => body.to_vec(),
        Err(error) => {
            crate::error::render_error_code(
                ErrorCode::JsonInvalid,
                res,
                &format!("unable to read request body: {error}"),
            );
            return None;
        }
    };
    match serde_json::from_slice::<T>(&body) {
        Ok(value) => Some((value, body)),
        Err(error) => {
            let code = if error.is_data() {
                ErrorCode::SchemaViolation
            } else {
                ErrorCode::JsonInvalid
            };
            crate::error::render_error_code(code, res, &format!("invalid request body: {error}"));
            None
        }
    }
}

fn state(depot: &Depot) -> Result<&AppState, String> {
    depot
        .get_typed::<AppState>()
        .map_err(|_| "authority service state is unavailable".to_owned())
}

fn validation_error(error: impl std::fmt::Display) -> String {
    format!("request does not match the current authority protocol: {error}")
}

fn invalid_application_output(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Internal(format!(
        "authority application returned an invalid current-protocol response: {error}"
    ))
}

fn render_result<T: Serialize + Send>(res: &mut Response, result: ServiceResult<T>) {
    match result {
        Ok(value) => res.render(Json(value)),
        Err(error) => render_service_error(res, error),
    }
}

pub(crate) fn render_service_error(res: &mut Response, error: ServiceError) {
    if error.conflict_code() == Some(coland_storage::ConflictCode::SnapshotCapacityExceeded) {
        return crate::error::render_error_with_reason_code(
            res,
            StatusCode::CONFLICT,
            "failed_precondition",
            &error.to_string(),
            coland_storage::ConflictCode::SnapshotCapacityExceeded.as_str(),
            None,
        );
    }
    if let ServiceError::Conflict(detail) = &error {
        let (token, detail) = detail.split_once(": ").unwrap_or(("", ""));
        // encryption-and-audit.md §5.1.2: a forwarded Genesis whose carried
        // material does not address its refs.
        if let Some(code @ (ErrorCode::DigestMismatch | ErrorCode::Unauthenticated)) =
            ErrorCode::from_wire(token)
        {
            return crate::error::render_error_code(code, res, detail);
        }
        match error.conflict_code() {
            Some(coland_storage::ConflictCode::EventIdDigestMismatch) => {
                return crate::error::render_error_with_reason_code(
                    res,
                    crate::error::error_http_status(ErrorCode::SchemaViolation),
                    ErrorCode::SCHEMA_VIOLATION,
                    "Event identity does not match its canonical content",
                    arkret_wire::ReasonCode::EVENT_ID_DIGEST_MISMATCH,
                    None,
                );
            }
            Some(coland_storage::ConflictCode::ApprovalNonceReused) => {
                return crate::error::render_error_with_reason_code(
                    res,
                    crate::error::error_http_status(ErrorCode::FailedPrecondition),
                    ErrorCode::FAILED_PRECONDITION,
                    detail,
                    arkret_wire::ReasonCode::APPROVAL_NONCE_REUSED,
                    None,
                );
            }
            Some(coland_storage::ConflictCode::ApprovalRequired) => {
                return crate::error::render_error_with_reason_code(
                    res,
                    crate::error::error_http_status(arkret_wire::ErrorCode::ClaimRequired),
                    arkret_wire::ErrorCode::CLAIM_REQUIRED,
                    detail,
                    arkret_wire::ReasonCode::APPROVAL_REQUIRED,
                    None,
                );
            }
            Some(coland_storage::ConflictCode::DuplicateConflict) => {
                return crate::error::render_error_code(
                    arkret_wire::ErrorCode::DuplicateConflict,
                    res,
                    detail,
                );
            }
            Some(coland_storage::ConflictCode::EpochMismatch) => {
                return crate::error::render_error_code(
                    arkret_wire::ErrorCode::EpochMismatch,
                    res,
                    detail,
                );
            }
            Some(coland_storage::ConflictCode::TemporarilyUnavailable) => {
                return crate::error::render_error_code(
                    arkret_wire::ErrorCode::TemporarilyUnavailable,
                    res,
                    detail,
                );
            }
            Some(coland_storage::ConflictCode::DidMethodSuccessorInvalid) => {
                return crate::error::render_error_code(
                    arkret_wire::ErrorCode::DidMethodSuccessorInvalid,
                    res,
                    detail,
                );
            }
            Some(coland_storage::ConflictCode::FailedPrecondition) => {
                return crate::error::render_error_code(
                    arkret_wire::ErrorCode::FailedPrecondition,
                    res,
                    detail,
                );
            }
            Some(coland_storage::ConflictCode::InvalidMembershipTransition) => {
                return crate::error::render_error_with_reason_code(
                    res,
                    crate::error::error_http_status(ErrorCode::FailedPrecondition),
                    ErrorCode::FAILED_PRECONDITION,
                    detail,
                    arkret_wire::ReasonCode::INVALID_MEMBERSHIP_TRANSITION,
                    None,
                );
            }
            Some(coland_storage::ConflictCode::InviteLiveTargetOccupied) => {
                // The detail is the occupant's exact create Event id; the
                // closed details are derived from it alone.
                if let Ok(create_event_id) = arkret_wire::EventId::new(detail.to_owned()) {
                    return crate::error::render_problem_envelope(
                        res,
                        crate::error::error_http_status(ErrorCode::FailedPrecondition),
                        arkret_wire::problem_details::Problem::invite_live_target_occupied(
                            "the invitee already has a live directed Invite in this Realm",
                            arkret_wire::InviteLiveTargetOccupiedProblem::new(create_event_id),
                        ),
                    );
                }
            }
            Some(coland_storage::ConflictCode::CapabilityDenied) => {
                return crate::error::render_error_code(
                    arkret_wire::ErrorCode::CapabilityDenied,
                    res,
                    detail,
                );
            }
            // capabilities.md §10.4: relinquish is subject-only; the refusal
            // does not reveal whether the target grant exists.
            Some(coland_storage::ConflictCode::GrantRelinquishNotSubject) => {
                return crate::error::render_error_with_reason_code(
                    res,
                    crate::error::error_http_status(arkret_wire::ErrorCode::CapabilityDenied),
                    arkret_wire::ErrorCode::CAPABILITY_DENIED,
                    "the actor is not the subject of the target grant",
                    arkret_wire::ReasonCode::GRANT_RELINQUISH_NOT_SUBJECT,
                    None,
                );
            }
            Some(coland_storage::ConflictCode::CasConflict) => {
                return crate::error::render_error_code(
                    arkret_wire::ErrorCode::CasConflict,
                    res,
                    detail,
                );
            }
            Some(coland_storage::ConflictCode::PolicyRevisionRollback) => {
                return crate::error::render_error_code(
                    arkret_wire::ErrorCode::PolicyRevisionRollback,
                    res,
                    detail,
                );
            }
            // constraint-schema.md section 8.1: an exhausted hard quota is
            // refused before any business effect, as `rate_limited`.
            Some(coland_storage::ConflictCode::RateLimited) => {
                return crate::error::render_error_code(
                    arkret_wire::ErrorCode::RateLimited,
                    res,
                    detail,
                );
            }
            Some(coland_storage::ConflictCode::RealmFrozen) => {
                return crate::error::render_error_code(
                    arkret_wire::ErrorCode::RealmFrozen,
                    res,
                    detail,
                );
            }
            // join-policy.md §4: an entry refused by its rule or gates is one
            // non-enumerating `gate_check_failed`, whatever gate failed.
            Some(coland_storage::ConflictCode::GateCheckFailed) => {
                return crate::error::render_error_with_reason_code(
                    res,
                    crate::error::error_http_status(arkret_wire::ErrorCode::CapabilityDenied),
                    arkret_wire::ErrorCode::CAPABILITY_DENIED,
                    "Realm entry was not admitted",
                    arkret_wire::ReasonCode::GATE_CHECK_FAILED,
                    None,
                );
            }
            // contact-and-direct-conversation.md section 5.5: another unit
            // already closed the founder's slot; carried under `conflict`.
            Some(coland_storage::ConflictCode::DirectConversationSlotAlreadyCommitted) => {
                return crate::error::render_error_with_reason_code(
                    res,
                    StatusCode::CONFLICT,
                    "conflict",
                    detail,
                    coland_storage::ConflictCode::DirectConversationSlotAlreadyCommitted.as_str(),
                    None,
                );
            }
            Some(
                code @ (coland_storage::ConflictCode::DirectConversationFoundingUnitInvalid
                | coland_storage::ConflictCode::DirectConversationSpaceForbidden
                | coland_storage::ConflictCode::CallStateTransitionInvalid
                | coland_storage::ConflictCode::EpochUpdateRequired
                | coland_storage::ConflictCode::MlsActivationRequired
                | coland_storage::ConflictCode::MlsActivationIrreversible
                | coland_storage::ConflictCode::GovernanceBindingMismatch
                | coland_storage::ConflictCode::JoinRulePolicyMismatch
                | coland_storage::ConflictCode::PolicyRevisionGap
                | coland_storage::ConflictCode::PinTargetNotPinned
                | coland_storage::ConflictCode::MimiRoomBindingMigrationProofInvalid
                | coland_storage::ConflictCode::InviteDirectedInviteeMismatch
                | coland_storage::ConflictCode::InviteKindRequiresRevoke
                | coland_storage::ConflictCode::InviteAlreadyTerminal
                | coland_storage::ConflictCode::StrandNotActive
                | coland_storage::ConflictCode::StrandNotArchived
                | coland_storage::ConflictCode::StrandAlreadyTerminal
                | coland_storage::ConflictCode::SpaceNotActive
                | coland_storage::ConflictCode::SpaceNotArchived
                | coland_storage::ConflictCode::SpaceAlreadyTerminal
                | coland_storage::ConflictCode::SpaceHasLiveDependents
                | coland_storage::ConflictCode::SpaceParentMismatch
                | coland_storage::ConflictCode::SpaceParentUnreadable
                | coland_storage::ConflictCode::SpaceRealmMismatch
                | coland_storage::ConflictCode::CrossRealmStructuralRelation
                | coland_storage::ConflictCode::GrantExceedsIssuerAuthority
                | coland_storage::ConflictCode::AuthorityCycle
                | coland_storage::ConflictCode::AuthorityExpiryWidening
                | coland_storage::ConflictCode::AccountabilityGrantMissing
                | coland_storage::ConflictCode::AgentGrantExceedsRequestedScope
                | coland_storage::ConflictCode::AgentRequestedScopeCommitmentInvalid
                | coland_storage::ConflictCode::AgentPcrGenesisDeclarationMissing
                | coland_storage::ConflictCode::ReducerProjectionFailed),
            ) => {
                return crate::error::render_error_with_reason_code(
                    res,
                    StatusCode::CONFLICT,
                    arkret_wire::ErrorCode::FAILED_PRECONDITION,
                    detail,
                    code.as_str(),
                    None,
                );
            }
            // Producer device and signature refusals (device-lifecycle
            // §8.2.2) keep their registered codes on both Event submit
            // operations, including an outcome relayed from the governance
            // Station.
            Some(code) => {
                let registered = match code {
                    coland_storage::ConflictCode::DeviceRevoked => {
                        Some(arkret_wire::ErrorCode::DeviceRevoked)
                    }
                    coland_storage::ConflictCode::DeviceRevocationPending => {
                        Some(arkret_wire::ErrorCode::DeviceRevocationPending)
                    }
                    coland_storage::ConflictCode::DeviceGenerationFenced => {
                        Some(arkret_wire::ErrorCode::DeviceGenerationFenced)
                    }
                    coland_storage::ConflictCode::DeviceUnauthorized => {
                        Some(arkret_wire::ErrorCode::DeviceUnauthorized)
                    }
                    coland_storage::ConflictCode::AppletRevoked => {
                        Some(arkret_wire::ErrorCode::AppletRevoked)
                    }
                    coland_storage::ConflictCode::AppletE2eeJoinUnauthorized => {
                        Some(arkret_wire::ErrorCode::AppletE2eeJoinUnauthorized)
                    }
                    coland_storage::ConflictCode::SignatureInvalid => {
                        Some(arkret_wire::ErrorCode::SignatureInvalid)
                    }
                    coland_storage::ConflictCode::SchemaViolation => {
                        Some(arkret_wire::ErrorCode::SchemaViolation)
                    }
                    _ => None,
                };
                if let Some(registered) = registered {
                    return crate::error::render_error_code(registered, res, detail);
                }
            }
            None => {}
        }
    }
    let (status, code) = match &error {
        ServiceError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
        ServiceError::Conflict(_)
            if error.conflict_code()
                == Some(coland_storage::ConflictCode::RecipientQueueAtCapacity) =>
        {
            (StatusCode::FORBIDDEN, "quota_exceeded")
        }
        ServiceError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
        ServiceError::SchemaViolation(_) => (
            crate::error::error_http_status(ErrorCode::SchemaViolation),
            ErrorCode::SCHEMA_VIOLATION,
        ),
        ServiceError::UnsupportedEventKind(_) => (
            crate::error::error_http_status(ErrorCode::UnsupportedEventKind),
            ErrorCode::UNSUPPORTED_EVENT_KIND,
        ),
        ServiceError::Database(_) | ServiceError::Internal(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    };
    let detail = if status == StatusCode::INTERNAL_SERVER_ERROR {
        "internal error".to_owned()
    } else {
        error.to_string()
    };
    // The canonical Problem envelope (type, title, status, detail, code), the
    // same one every other refusal of this operation carries.
    crate::error::render_error(res, status, code, &detail);
}

async fn submit_managed_device(
    app_state: &AppState,
    req: &mut Request,
    device: &crate::routing::identity::applet_managed_device::VerifiedAppletManagedDevice,
    res: &mut Response,
) {
    no_store(res);
    if device.operation != arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1 {
        return crate::error::render_error_code(
            ErrorCode::Unauthenticated,
            res,
            "managed operation differs from actual route",
        );
    }
    let Some((request, _exact_body)) =
        parse_exact_closed_body::<SelfAuthoritySubmitRequestBody>(req, res).await
    else {
        return;
    };
    if let Err(error) = request.validate() {
        return crate::error::render_error_code(
            ErrorCode::SchemaViolation,
            res,
            &validation_error(error),
        );
    }
    let result = app_state
        .authority()
        .submit_managed_device(&device.metadata, &device.authority, request.clone())
        .await
        .and_then(|outcome| {
            outcome
                .validate_for_request(&request)
                .map_err(invalid_application_output)?;
            Ok(outcome)
        });
    match result {
        Ok(outcome) => res.render(Json(outcome)),
        Err(error) => render_service_error(res, error),
    }
}

#[handler]
pub(crate) async fn submit_self(req: &mut Request, depot: &Depot, res: &mut Response) {
    #[cfg(feature = "conformance-harness")]
    tracing::warn!(
        phase = "handler_entered",
        "self submission execution boundary"
    );
    let app_state = match state(depot) {
        Ok(state) => state,
        Err(error) => {
            return crate::error::render_error_code(ErrorCode::InternalError, res, &error);
        }
    };
    if let Ok(control) = depot
        .get_typed::<crate::routing::identity::realm_actor_control::VerifiedRealmActorControl>(
    ) {
        return submit_applet_control(app_state, req, control, res).await;
    }
    if let Ok(device) = depot
        .get_typed::<crate::routing::identity::applet_managed_device::VerifiedAppletManagedDevice>(
    ) {
        return submit_managed_device(app_state, req, device, res).await;
    }
    if req.headers().contains_key("source-service-id") {
        return submit_realm_actor_service(app_state, req, res).await;
    }
    let Some(session) = crate::routing::auth_or_render(app_state, req, res).await else {
        #[cfg(feature = "conformance-harness")]
        trace_submission_refusal("authentication", "unparsed", "unresolved", None);
        return;
    };
    #[cfg(feature = "conformance-harness")]
    tracing::warn!(
        phase = "authenticated",
        "self submission execution boundary"
    );
    if let Err(error) =
        crate::routing::identity::session_actor::validated_session_actor(app_state, &session).await
    {
        #[cfg(feature = "conformance-harness")]
        trace_submission_refusal("session_actor", "unparsed", "unresolved", None);
        return crate::routing::render_error(
            res,
            error.http_status(),
            error.wire_code(),
            &error.message,
        );
    }
    if let Err(error) = crate::routing::events::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
    ) {
        #[cfg(feature = "conformance-harness")]
        trace_submission_refusal("agent_operation_scope", "unparsed", "agent", None);
        return crate::routing::render_error(
            res,
            error.http_status(),
            error.wire_code(),
            &error.message,
        );
    }
    let Some((request, exact_request_body)) =
        parse_exact_closed_body::<SelfAuthoritySubmitRequestBody>(req, res).await
    else {
        return;
    };
    if let Err(error) = request.validate() {
        return crate::error::render_error_code(
            ErrorCode::SchemaViolation,
            res,
            &validation_error(error),
        );
    }
    let authority = app_state.authority();
    #[cfg(feature = "conformance-harness")]
    tracing::warn!(
        phase = "authority_dispatch",
        "self submission execution boundary"
    );
    let result = authority
        .submit_self(&session, request.clone(), &exact_request_body)
        .await
        .and_then(|outcome| {
            outcome
                .validate_for_request(&request)
                .map_err(invalid_application_output)?;
            Ok(outcome)
        });
    #[cfg(feature = "conformance-harness")]
    tracing::warn!(
        phase = "authority_returned",
        "self submission execution boundary"
    );
    #[cfg(feature = "conformance-harness")]
    if let Err(error) = &result {
        let kind_class = match &request {
            SelfAuthoritySubmitRequestBody::Event(value) => {
                submission_kind_class(&value.event.kind)
            }
            SelfAuthoritySubmitRequestBody::MlsCommit(_) => "mls",
            SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(_) => "realm_bootstrap",
            SelfAuthoritySubmitRequestBody::DirectConversationFounding(_) => "direct_founding",
            SelfAuthoritySubmitRequestBody::MembershipCompensation(_) => "membership_compensation",
            SelfAuthoritySubmitRequestBody::AuditPairedEvent(_) => "audit_paired_event",
        };
        let actor_class = if session.agent_session().is_some() {
            "agent"
        } else {
            "human"
        };
        trace_submission_refusal("authority_dispatch", kind_class, actor_class, Some(error));
    }
    if let Ok(
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::Ordinary(
            arkret_wire::AuthoritySubmitResponseBody::Accepted {
                status: arkret_wire::AuthorityCommitStatus::Committed,
                ..
            },
        ),
    ) = &result
    {
        let event_id = match &request {
            SelfAuthoritySubmitRequestBody::Event(submission) => {
                Some(submission.event.event_id.as_str())
            }
            SelfAuthoritySubmitRequestBody::MlsCommit(submission) => {
                Some(submission.commit_event.event_id.as_str())
            }
            _ => None,
        };
        if let Some(event_id) = event_id {
            // The guarded unit stored the projected Event in the same
            // transaction as its Commit. Broadcast only the durable row: the
            // payload is also consumed by the committed-event live rail.
            match app_state.event_queries().projected_event(event_id).await {
                Ok(Some(projected)) => {
                    let _ = app_state.publish_event_notification(
                        crate::state::EventNotification::event(
                            projected.realm_id.clone(),
                            projected.event_id.clone(),
                            crate::routing::events::projection::projection_event_json(&projected),
                        ),
                    );
                }
                Ok(None) => tracing::warn!(
                    event_id,
                    "committed Event projection is not readable for live wakeup"
                ),
                Err(error) => {
                    tracing::warn!(event_id, %error, "committed Event projection lookup failed for live wakeup")
                }
            }
        }
    }
    if let Err(error @ (ServiceError::Database(_) | ServiceError::Internal(_))) = &result {
        tracing::error!(error = %error, "self authority submission failed internally");
    }
    render_result(res, result);
}

async fn submit_realm_actor_service(state: &AppState, req: &mut Request, res: &mut Response) {
    let operation = arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1;
    if req.headers().get_all("arkret-operation").iter().count() != 1
        || req
            .headers()
            .get("arkret-operation")
            .and_then(|value| value.to_str().ok())
            != Some(operation.as_str())
    {
        return crate::error::render_error_code(
            ErrorCode::CapabilityDenied,
            res,
            "creation operation differs from route",
        );
    }
    let service =
        match crate::routing::extensions::applet_bridge::verify_self_control_service(state, req)
            .await
        {
            Ok(service) => service,
            Err(error) => {
                return crate::routing::render_error(
                    res,
                    error.http_status(),
                    error.wire_code(),
                    &error.message,
                );
            }
        };
    let Some((request, _)) =
        parse_exact_closed_body::<SelfAuthoritySubmitRequestBody>(req, res).await
    else {
        return;
    };
    let result = async {
        request
            .validate()
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        let SelfAuthoritySubmitRequestBody::Event(submission) = &request else {
            return Err(ServiceError::SchemaViolation(
                "Service creation requires one original Event".into(),
            ));
        };
        let event = &submission.event;
        if !matches!(
            event.kind,
            arkret_wire::EventKind::RealmActorCreate
                | arkret_wire::EventKind::RealmActorRecoveryBegin
                | arkret_wire::EventKind::RealmActorControlReset
        ) || event.actor_id != arkret_wire::ActorId::service(service.service_id.clone())
            || event.executed_by.is_some()
            || service.expires_at <= chrono::Utc::now()
        {
            return Err(ServiceError::Conflict(
                "capability_denied: creation does not match its authenticated Service".into(),
            ));
        }
        let digest = arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&request)
                .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?,
        )
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        let recovery = matches!(
            event.kind,
            arkret_wire::EventKind::RealmActorRecoveryBegin
                | arkret_wire::EventKind::RealmActorControlReset
        );
        if recovery && submission.approval_signatures.is_some() {
            return Err(ServiceError::SchemaViolation(
                "recovery uses its registered maintenance authority".into(),
            ));
        }
        let replay = if recovery {
            state
                .authority_commits()
                .realm_actor_recovery_replay(event, &digest, &state.service_core_id())
                .await?
        } else {
            state
                .authority_commits()
                .realm_actor_creation_replay(event, &digest, &state.service_core_id())
                .await?
        };
        let outcome = if let Some(commit) = replay {
            arkret_wire::AuthoritySubmitResponseBody::Accepted {
                status: arkret_wire::AuthorityCommitStatus::Duplicate,
                commit,
            }
        } else {
            let target = arkret_models_integration::ManagementReviewTarget::Event {
                event: Box::new(event.clone()),
            };
            let current =
                crate::routing::extensions::applet_bridge::prepare_event_current(state, &target)
                    .await?
                    .ok_or_else(|| {
                        ServiceError::Conflict(
                            "revision_unavailable: creation Service document absent".into(),
                        )
                    })?;
            let producer = coland_storage::AppletEventProducerGuard {
                service_did_document: current.service_did_document,
            };
            let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
            let approvals =
                crate::approval_admission::prepare_event_approvals(state, submission, at).await?;
            let method = arkret_wire::DidUrl::new(
                crate::routing::federation::federation_service_signature_key_id(
                    state.service_did().as_str(),
                ),
            )
            .map_err(|e| ServiceError::Internal(e.to_string()))?;
            if recovery {
                use coland_services::identity::DidResolverPort as _;
                let publication = if event.kind == arkret_wire::EventKind::RealmActorControlReset {
                    let payload: arkret_models_integration::RealmActorControlResetPayload =
                        serde_json::from_value(serde_json::json!(event.payload))
                            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
                    let (_, entries, _) =
                        payload.published_method_history_evidence.webvh_material();
                    let did = entries
                        .last()
                        .and_then(|entry| entry.get("state"))
                        .and_then(|state| state.get("id"))
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            ServiceError::SchemaViolation("published recovery DID absent".into())
                        })?;
                    let did = arkret_wire::Did::new(did.to_owned())
                        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
                    let resolver =
                        crate::state::did_resolver_chain::build_coland_did_resolver(state.config());
                    let current = resolver
                        .resolve_current_external_webvh_state(&did)
                        .await
                        .map_err(|e| {
                            ServiceError::Conflict(format!(
                                "temporarily_unavailable: recovery publication unavailable: {e}"
                            ))
                        })?;
                    Some(arkret_models_identity::ResolutionCommitment {
                        did: current.did,
                        version_id: current.version_id,
                        method_history_head: current.log_head_digest.to_string(),
                    })
                } else {
                    None
                };
                state
                    .authority_commits()
                    .admit_realm_actor_recovery(
                        event,
                        &producer,
                        publication.as_ref(),
                        &state.service_core_id(),
                        method,
                        state.notary_signing_key().as_ref(),
                        at,
                        &digest,
                    )
                    .await?
            } else {
                state
                    .authority_commits()
                    .admit_realm_actor_creation(
                        event,
                        &producer,
                        &state.service_core_id(),
                        method,
                        state.notary_signing_key().as_ref(),
                        at,
                        approvals.as_ref(),
                        &digest,
                    )
                    .await?
            }
        };
        let outcome =
            arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::Ordinary(
                outcome,
            );
        outcome
            .validate_for_request(&request)
            .map_err(invalid_application_output)?;
        Ok(outcome)
    }
    .await;
    no_store(res);
    render_result(res, result);
}

async fn submit_applet_control(
    app_state: &AppState,
    req: &mut Request,
    control: &crate::routing::identity::realm_actor_control::VerifiedRealmActorControl,
    res: &mut Response,
) {
    let source = &control.carrier;
    let Some((request, _)) =
        parse_exact_closed_body::<SelfAuthoritySubmitRequestBody>(req, res).await
    else {
        return;
    };
    let result = async {
        request
            .validate()
            .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        let SelfAuthoritySubmitRequestBody::Event(submission) = &request else {
            return Err(ServiceError::SchemaViolation(
                "Realm control ingress requires one original Event submission".into(),
            ));
        };
        if control.operation != arkret_wire::ServiceOperationId::SelfEventsCommandSubmitV1
            || control.expires_at <= chrono::Utc::now()
            || submission.event.actor_id != source.actor_id
            || !matches!(
                submission.event.kind,
                arkret_wire::EventKind::DeviceAuthorize
                    | arkret_wire::EventKind::DeviceRevoke
                    | arkret_wire::EventKind::RealmActorStatusSet
                    | arkret_wire::EventKind::RealmActorDevicesReset
                    | arkret_wire::EventKind::RealmActorControlUpdate
                    | arkret_wire::EventKind::RealmActorManagerChange
                    | arkret_wire::EventKind::ProfileCreate
                    | arkret_wire::EventKind::ProfileUpdate
            )
            || (!matches!(
                submission.event.kind,
                arkret_wire::EventKind::ProfileCreate
                    | arkret_wire::EventKind::ProfileUpdate
                    | arkret_wire::EventKind::RealmActorManagerChange
            ) && submission.approval_signatures.is_some())
        {
            return Err(ServiceError::SchemaViolation(
                "this control command does not match the authenticated subject".into(),
            ));
        }
        let method = arkret_wire::DidUrl::new(
            crate::routing::federation::federation_service_signature_key_id(
                app_state.service_did().as_str(),
            ),
        )
        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?;
        let request_digest = arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&request)
                .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?,
        )
        .map_err(|error| ServiceError::SchemaViolation(error.to_string()))?;
        let replay = app_state
            .authority_commits()
            .realm_actor_control_replay(&submission.event, source, &request_digest)
            .await?;
        let outcome = if let Some(commit) = replay {
            arkret_wire::AuthoritySubmitResponseBody::Accepted {
                status: arkret_wire::AuthorityCommitStatus::Duplicate,
                commit,
            }
        } else if matches!(
            submission.event.kind,
            arkret_wire::EventKind::ProfileCreate | arkret_wire::EventKind::ProfileUpdate
        ) {
            let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
            let prepared =
                crate::approval_admission::prepare_event_approvals(app_state, submission, at)
                    .await?;
            app_state
                .authority_commits()
                .admit_realm_actor_profile(
                    &submission.event,
                    source,
                    &app_state.service_core_id(),
                    method,
                    app_state.notary_signing_key().as_ref(),
                    at,
                    prepared.as_ref(),
                    &request_digest,
                )
                .await?
        } else if matches!(
            submission.event.kind,
            arkret_wire::EventKind::RealmActorStatusSet
                | arkret_wire::EventKind::RealmActorDevicesReset
                | arkret_wire::EventKind::RealmActorControlUpdate
                | arkret_wire::EventKind::RealmActorManagerChange
                | arkret_wire::EventKind::DeviceRevoke
        ) {
            let publication = if matches!(
                submission.event.kind,
                arkret_wire::EventKind::RealmActorControlUpdate
                    | arkret_wire::EventKind::RealmActorManagerChange
            ) {
                use coland_services::identity::DidResolverPort as _;
                let next_resolution =
                    if submission.event.kind == arkret_wire::EventKind::RealmActorManagerChange {
                        serde_json::from_value::<
                            arkret_models_integration::RealmActorManagerChangePayload,
                        >(serde_json::json!(submission.event.payload))
                        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?
                        .next_resolution
                    } else {
                        serde_json::from_value::<
                            arkret_models_integration::RealmActorControlUpdatePayload,
                        >(serde_json::json!(submission.event.payload))
                        .map_err(|e| ServiceError::SchemaViolation(e.to_string()))?
                        .next_resolution
                    };
                let resolver =
                    crate::state::did_resolver_chain::build_coland_did_resolver(app_state.config());
                let current = resolver
                    .resolve_current_external_webvh_state(&next_resolution.did)
                    .await
                    .map_err(|e| {
                        ServiceError::Conflict(format!(
                            "temporarily_unavailable: control publication unavailable: {e}"
                        ))
                    })?;
                Some(arkret_models_identity::ResolutionCommitment {
                    did: current.did,
                    version_id: current.version_id,
                    method_history_head: current.log_head_digest.to_string(),
                })
            } else {
                None
            };
            let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
            let (manager, prepared) = if submission.event.kind
                == arkret_wire::EventKind::RealmActorManagerChange
            {
                let target =
                    arkret_models_integration::management_review::ManagementReviewTarget::Event {
                        event: Box::new(submission.event.clone()),
                    };
                let current = crate::routing::extensions::applet_bridge::prepare_event_current(
                    app_state, &target,
                )
                .await?
                .ok_or_else(|| {
                    ServiceError::Conflict("receiving Service document unavailable".into())
                })?;
                let prepared =
                    crate::approval_admission::prepare_event_approvals(app_state, submission, at)
                        .await?;
                (
                    Some(coland_storage::AppletEventProducerGuard {
                        service_did_document: current.service_did_document,
                    }),
                    prepared,
                )
            } else {
                (None, None)
            };
            app_state
                .authority_commits()
                .admit_realm_actor_owner_control(
                    &submission.event,
                    source,
                    publication.as_ref(),
                    manager.as_ref(),
                    prepared.as_ref(),
                    &app_state.service_core_id(),
                    method,
                    app_state.notary_signing_key().as_ref(),
                    at,
                    &request_digest,
                )
                .await?
        } else {
            let outcome = app_state
                .authority_commits()
                .admit_applet_managed_device_authorization(
                    &submission.event,
                    source,
                    &app_state.service_core_id(),
                    method,
                    app_state.notary_signing_key().as_ref(),
                    &request_digest,
                )
                .await?;
            use coland_services::authority_commit::AuthorityEventAdmissionOutcome;

            match outcome {
                AuthorityEventAdmissionOutcome::Committed(commit) => {
                    arkret_wire::AuthoritySubmitResponseBody::Accepted {
                        status: arkret_wire::AuthorityCommitStatus::Committed,
                        commit,
                    }
                }
                AuthorityEventAdmissionOutcome::Duplicate(commit) => {
                    arkret_wire::AuthoritySubmitResponseBody::Accepted {
                        status: arkret_wire::AuthorityCommitStatus::Duplicate,
                        commit,
                    }
                }
                AuthorityEventAdmissionOutcome::NotCurrentAuthority => {
                    return Err(ServiceError::Conflict(
                        "stale_realm_authority: subject Realm is not governed here".into(),
                    ));
                }
            }
        };
        let outcome =
            arkret_models_collaboration::authority_commit::SelfAuthoritySubmitResponseBody::Ordinary(
                outcome,
            );
        outcome
            .validate_for_request(&request)
            .map_err(invalid_application_output)?;
        Ok(outcome)
    }
    .await;
    if let Err(error @ (ServiceError::Database(_) | ServiceError::Internal(_))) = &result {
        tracing::error!(error = %error, "Realm control submission failed internally");
    }
    render_result(res, result);
}

#[handler]
async fn scan_stream(req: &mut Request, depot: &Depot, res: &mut Response) {
    let app_state = match state(depot) {
        Ok(state) => state,
        Err(error) => {
            return crate::error::render_error_code(ErrorCode::InternalError, res, &error);
        }
    };
    if let Ok(device) = depot
        .get_typed::<crate::routing::identity::applet_managed_device::VerifiedAppletManagedDevice>(
    ) {
        let Some(request) = parse_closed_body::<StreamScanRequestBody>(req, res).await else {
            return;
        };
        match native_stream_scan(app_state, device, request).await {
            Ok(outcome) => {
                no_store(res);
                salvo::Scribe::render(outcome, res);
            }
            Err(error) => crate::routing::render_error(
                res,
                error.http_status(),
                error.wire_code(),
                &error.message,
            ),
        }
        return;
    }
    let Some(session) = crate::routing::auth_or_render(app_state, req, res).await else {
        #[cfg(feature = "conformance-harness")]
        trace_stream_read_refusal("authentication", "other", None);
        return;
    };
    let actor =
        match crate::routing::identity::session_actor::validated_session_actor(app_state, &session)
            .await
        {
            Ok(actor) => actor,
            Err(error) => {
                #[cfg(feature = "conformance-harness")]
                trace_stream_read_refusal(
                    "session_actor",
                    "other",
                    ErrorCode::from_wire(error.wire_code()),
                );
                return crate::routing::render_error(
                    res,
                    error.http_status(),
                    error.wire_code(),
                    &error.message,
                );
            }
        };
    if let Err(error) = crate::routing::events::require_agent_session_scope(
        &session,
        arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
    ) {
        #[cfg(feature = "conformance-harness")]
        trace_stream_read_refusal(
            "agent_operation_scope",
            "other",
            ErrorCode::from_wire(error.wire_code()),
        );
        return crate::routing::render_error(
            res,
            error.http_status(),
            error.wire_code(),
            &error.message,
        );
    }
    let Some(request) = parse_closed_body::<StreamScanRequestBody>(req, res).await else {
        return;
    };
    if let Err(error) = request.validate() {
        return crate::error::render_error_code(
            ErrorCode::SchemaViolation,
            res,
            &validation_error(error),
        );
    }
    // Stream readability is decided for an Account member; an actor with no
    // Account has no readable interval on any Realm stream here.
    let Some(account) = actor.as_account_id() else {
        #[cfg(feature = "conformance-harness")]
        trace_stream_read_refusal(
            "account_actor_required",
            diagnostic_stream_class(&request),
            Some(ErrorCode::CapabilityDenied),
        );
        return crate::error::render_error_code(
            ErrorCode::CapabilityDenied,
            res,
            "the stream is not readable by this caller",
        );
    };
    let result = app_state
        .authority()
        .scan_stream_for_account(account, request.clone())
        .await;
    tracing::debug!(target: "sync_network",
        after_position = match request.direction { arkret_wire::StreamScanDirection::After(position) => position, _ => None },
        stream_kind = match request.stream_ref { arkret_wire::CommitStreamRef::Realm {..} => "realm", arkret_wire::CommitStreamRef::Circle {..} => "circle", arkret_wire::CommitStreamRef::Sidecar {..} => "sidecar", _ => "unknown" },
        "authorized stream scan direction");
    render_stream_scan(res, &request, result);
}

async fn native_stream_scan(
    state: &AppState,
    device: &crate::routing::identity::applet_managed_device::VerifiedAppletManagedDevice,
    request: StreamScanRequestBody,
) -> coland_http::result::GuardedJsonResult<arkret_wire::StreamScanResponseBody> {
    let unavailable =
        || coland_http::error::AppError::capability_denied("native stream content is unavailable");
    request
        .validate()
        .map_err(|e| coland_http::error::AppError::schema_violation(e.to_string()))?;
    if device.operation != arkret_wire::ServiceOperationId::SelfCommittedEventReadScanV1
        || request.stream_ref.scope_ref() != device.metadata.effective_scope
        || !matches!(
            device.metadata.effective_scope,
            arkret_wire::ScopeRef::Realm { .. } | arkret_wire::ScopeRef::Circle { .. }
        )
    {
        return Err(unavailable());
    }
    let result = state
        .authority_commits()
        .scan_stream_for_actor(
            &request,
            &device.authority.actor_id,
            &state.service_core_id(),
        )
        .await
        .map_err(|_| unavailable())?;
    let coland_storage::AccountStreamScan::Page(outcome) = result else {
        return Err(unavailable());
    };
    let outcome = outcome
        .into_effective_scope(&device.metadata.effective_scope)
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    outcome
        .validate_for_request(&request)
        .map_err(|_| unavailable())?;
    let input = coland_storage::AccountContentDeliveryInput {
        realms: vec![request.realm_id.clone()],
        stream_scans: vec![(request, outcome.clone())],
        ..Default::default()
    };
    let guard = crate::routing::identity::applet_managed_device::content_delivery_guard_for_input(
        state, device, input,
    )
    .await
    .map_err(|_| unavailable())?;
    coland_http::result::guarded_json_ok(outcome, Some(guard))
}

/// Render one caller-scoped scan decision. A refused caller receives the
/// universal non-enumerating `capability_denied`; an interval this Station
/// cannot prove fails closed as `temporarily_unavailable`, never as a page.
fn render_stream_scan(
    res: &mut Response,
    request: &StreamScanRequestBody,
    result: ServiceResult<coland_storage::AccountStreamScan>,
) {
    match result {
        Ok(coland_storage::AccountStreamScan::Page(outcome)) => {
            if let Err(error) = outcome.validate_for_request(request) {
                return render_service_error(res, invalid_application_output(error));
            }
            no_store(res);
            res.render(Json(outcome));
        }
        Ok(coland_storage::AccountStreamScan::NotAuthorized) => {
            #[cfg(feature = "conformance-harness")]
            trace_stream_read_refusal(
                "stream_readability",
                diagnostic_stream_class(request),
                Some(ErrorCode::CapabilityDenied),
            );
            crate::error::render_error_code(
                ErrorCode::CapabilityDenied,
                res,
                "the stream is not readable by this caller",
            );
        }
        Ok(coland_storage::AccountStreamScan::Unproved(reason)) => {
            #[cfg(feature = "conformance-harness")]
            trace_stream_read_refusal(
                "interval_unproved",
                diagnostic_stream_class(request),
                Some(ErrorCode::TemporarilyUnavailable),
            );
            tracing::info!(realm_id = %request.realm_id, reason,
                "stream scan interval is not provable at this cut");
            crate::error::render_error_code(
                ErrorCode::TemporarilyUnavailable,
                res,
                "the caller's readable interval cannot be proved at this cut",
            );
        }
        Err(error) => {
            #[cfg(feature = "conformance-harness")]
            trace_stream_read_refusal(
                "scan_storage",
                diagnostic_stream_class(request),
                error
                    .conflict_code()
                    .and_then(|code| ErrorCode::from_wire(code.as_str())),
            );
            render_service_error(res, error);
        }
    }
}
fn render_peer_stream_scan(
    res: &mut Response,
    request: &StreamScanRequestBody,
    result: ServiceResult<coland_storage::PeerStreamScan>,
) {
    match result {
        Ok(coland_storage::PeerStreamScan::Page(outcome)) => {
            if let Err(error) = outcome.validate_for_request(request) {
                return render_service_error(res, invalid_application_output(error));
            }
            no_store(res);
            res.render(Json(outcome));
        }
        Ok(coland_storage::PeerStreamScan::NotAuthorized) => {
            #[cfg(feature = "conformance-harness")]
            trace_stream_read_refusal(
                "stream_readability",
                diagnostic_stream_class(request),
                Some(ErrorCode::CapabilityDenied),
            );
            crate::error::render_error_code(
                ErrorCode::CapabilityDenied,
                res,
                "the stream is not readable by this caller",
            );
        }
        Ok(coland_storage::PeerStreamScan::Unproved(reason)) => {
            #[cfg(feature = "conformance-harness")]
            trace_stream_read_refusal(
                "interval_unproved",
                diagnostic_stream_class(request),
                Some(ErrorCode::TemporarilyUnavailable),
            );
            tracing::info!(realm_id = %request.realm_id, reason,
                "stream scan interval is not provable at this cut");
            crate::error::render_error_code(
                ErrorCode::TemporarilyUnavailable,
                res,
                "the caller's readable interval cannot be proved at this cut",
            );
        }
        Err(error) => {
            #[cfg(feature = "conformance-harness")]
            trace_stream_read_refusal(
                "scan_storage",
                diagnostic_stream_class(request),
                error
                    .conflict_code()
                    .and_then(|code| ErrorCode::from_wire(code.as_str())),
            );
            render_service_error(res, error);
        }
    }
}

/// `POST /_arkret/peer/streams/scan`. The caller is the peer Station proved
/// by the RFC 9421 service signature (with the inbound deny policy); the
/// body never names it. The replication right is decided on the governing
/// read cut, with the same closed request contract as the self scan.
#[handler]
async fn peer_scan_stream(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let app_state = match state(depot) {
        Ok(state) => state.clone(),
        Err(error) => {
            return crate::error::render_error_code(ErrorCode::InternalError, res, &error);
        }
    };
    let peer = match crate::routing::events::peer::authenticated_peer_context(&app_state, req, true)
        .await
    {
        Ok(peer) => peer,
        Err(error) => return error.write(req, depot, res).await,
    };
    let Some(request) = parse_closed_body::<StreamScanRequestBody>(req, res).await else {
        return;
    };
    if let Err(error) = request.validate() {
        return crate::error::render_error_code(
            ErrorCode::SchemaViolation,
            res,
            &validation_error(error),
        );
    }
    let result = app_state
        .authority()
        .scan_stream_for_peer(&peer, request.clone())
        .await;
    render_peer_stream_scan(res, &request, result);
}

#[handler]
async fn peer_handoff(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let app_state = match state(depot) {
        Ok(state) => state.clone(),
        Err(error) => {
            return crate::error::render_error_code(ErrorCode::InternalError, res, &error);
        }
    };
    let peer = match crate::routing::events::peer::authenticated_peer_context(&app_state, req, true)
        .await
    {
        Ok(peer) => peer,
        Err(error) => return error.write(req, depot, res).await,
    };
    let Some(request) = parse_closed_body::<
        arkret_models_collaboration::authority_commit::AuthorityRealmAuthorityHandoffRequestBody,
    >(req, res)
    .await
    else {
        return;
    };
    // The application checks fixed-governance eligibility from the original
    // genesis before validating a successor bundle. Its typed precondition
    // refusal must retain the same error code at the HTTP boundary.
    let result = app_state
        .authority()
        .install_authority_handoff(&peer, request)
        .await;
    no_store(res);
    render_result(res, result);
}

#[handler]
async fn authority_bundle(req: &mut Request, depot: &Depot, res: &mut Response) {
    let Some(request) = parse_closed_body::<RealmAuthorityBundleRequestBody>(req, res).await else {
        return;
    };
    if let Err(error) = request.validate() {
        return crate::error::render_error_code(
            ErrorCode::SchemaViolation,
            res,
            &validation_error(error),
        );
    }
    if let Ok(app) = state(depot) {
        match app
            .persistence()
            .principal_resolution_for_realm(&request.realm_id)
            .await
        {
            Ok(Some(origin))
                if arkret_wire::GenesisGovernance::from_genesis(&origin.genesis_event)
                    .is_ok_and(|g| g.is_human()) =>
            {
                return crate::error::render_error_code(
                    ErrorCode::NotFound,
                    res,
                    "Realm authority not found",
                );
            }
            Err(error) => {
                tracing::debug!(%error,"private inception lookup unavailable");
                return crate::error::render_error_code(
                    ErrorCode::NotFound,
                    res,
                    "Realm authority not found",
                );
            }
            _ => {}
        }
    }
    let authority = match state(depot) {
        Ok(state) => state.authority(),
        Err(error) => {
            return crate::error::render_error_code(ErrorCode::InternalError, res, &error);
        }
    };
    let result = authority
        .authority_bundle(request.clone())
        .await
        .and_then(|outcome| {
            outcome
                .validate_for_request(&request, chrono::Utc::now())
                .map_err(invalid_application_output)?;
            match arkret_wire::GenesisGovernance::from_genesis(&outcome.genesis_event) {
                Ok(governance) if !governance.is_human() => Ok(outcome),
                _ => Err(ServiceError::NotFound("Realm authority not found".into())),
            }
        });
    match result {
        Ok(bundle) => {
            no_store(res);
            res.render(Json(bundle));
        }
        // Human PCRs and absent Realms have the same non-enumerating refusal.
        Err(ServiceError::NotFound(_)) => {
            crate::error::render_error_code(ErrorCode::NotFound, res, "Realm authority not found")
        }
        Err(error) => render_service_error(res, error),
    }
}

#[cfg(test)]
mod tests {
    use salvo::test::{ResponseExt as _, TestClient};

    use super::*;

    #[tokio::test]
    async fn direct_handoff_eligibility_refusal_retains_failed_precondition() {
        let mut res = Response::new();
        render_service_error(
            &mut res,
            ServiceError::Conflict(
                "failed_precondition: Direct Conversation governance cannot transfer".to_owned(),
            ),
        );
        assert_eq!(res.status_code, Some(StatusCode::CONFLICT));
        let body: serde_json::Value = res.take_json().await.unwrap();
        assert_eq!(
            body["type"],
            "https://arkret.org/problems/failed_precondition"
        );
        assert_eq!(body["status"], 409);
    }

    #[test]
    fn mounted_authority_routes_are_the_registered_canonical_paths() {
        for (path, operation) in [
            (
                "/_arkret/self/streams/scan",
                arkret_wire::ServiceOperationId::SelfCommittedEventReadScanV1,
            ),
            (
                "/_arkret/peer/streams/scan",
                arkret_wire::ServiceOperationId::PeerCommittedEventReadScanV1,
            ),
            (
                "/_arkret/open/realm-authority/bundle",
                arkret_wire::ServiceOperationId::OpenRealmAuthorityReadBundleV1,
            ),
        ] {
            let descriptor = operation.descriptor();
            assert_eq!(descriptor.http_path, path);
            assert_eq!(descriptor.http_method, "POST");
        }
    }

    #[tokio::test]
    async fn event_identity_mismatch_renders_schema_violation_not_duplicate_conflict() {
        for detail in [
            "event_id_digest_mismatch",
            "event_id_digest_mismatch: carried Event ID differs from its preimage",
        ] {
            let mut res = Response::new();
            render_service_error(&mut res, ServiceError::Conflict(detail.to_owned()));
            assert_eq!(res.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
            let body: serde_json::Value = res.take_json().await.expect("problem body");
            assert_eq!(body["status"], 422);
            assert_eq!(body["type"], "https://arkret.org/problems/schema_violation");
            assert_eq!(body["reason_code"], "event_id_digest_mismatch");
        }
    }

    #[tokio::test]
    async fn snapshot_capacity_overflow_renders_the_registered_precondition_reason() {
        let mut res = Response::new();
        render_service_error(
            &mut res,
            ServiceError::Conflict(
                "snapshot_capacity_exceeded: candidate Realm snapshot exceeds 8 MiB".to_owned(),
            ),
        );
        assert_eq!(res.status_code, Some(StatusCode::CONFLICT));
        let body: serde_json::Value = salvo::test::ResponseExt::take_json(&mut res)
            .await
            .expect("problem body");
        assert_eq!(body["status"], 409);
        assert_eq!(
            body["type"],
            "https://arkret.org/problems/failed_precondition"
        );
        assert_eq!(body["reason_code"], "snapshot_capacity_exceeded");
    }

    #[tokio::test]
    async fn membership_fsm_failure_renders_registered_reason() {
        let mut res = Response::new();
        render_service_error(
            &mut res,
            ServiceError::Conflict(
                "invalid_membership_transition: membership transition is not a listed edge"
                    .to_owned(),
            ),
        );
        assert_eq!(res.status_code, Some(StatusCode::CONFLICT));
        let body: serde_json::Value = salvo::test::ResponseExt::take_json(&mut res).await.unwrap();
        assert_eq!(
            body["type"],
            "https://arkret.org/problems/failed_precondition"
        );
        assert_eq!(body["reason_code"], "invalid_membership_transition");
    }

    #[tokio::test]
    async fn recovery_actor_mismatch_retains_the_registered_authentication_error() {
        let mut res = Response::new();
        render_service_error(
            &mut res,
            ServiceError::Conflict(
                "unauthenticated: recovery credential does not bind the exact original Account"
                    .to_owned(),
            ),
        );
        assert_eq!(res.status_code, Some(StatusCode::UNAUTHORIZED));
        let body: serde_json::Value = res.take_json().await.expect("problem body");
        assert_eq!(body["type"], "https://arkret.org/problems/unauthenticated");
    }

    #[tokio::test]
    async fn approval_nonce_rebinding_renders_registered_precondition_reason() {
        let mut res = Response::new();
        render_service_error(&mut res, ServiceError::Conflict(
            "approval_nonce_reused: a controller nonce cannot bind different confirmation bytes".to_owned(),
        ));
        assert_eq!(res.status_code, Some(StatusCode::CONFLICT));
        let body: serde_json::Value = res.take_json().await.expect("problem body");
        assert_eq!(
            body["type"],
            "https://arkret.org/problems/failed_precondition"
        );
        assert_eq!(body["reason_code"], "approval_nonce_reused");
    }

    #[tokio::test]
    async fn list_wip_review_without_verified_vote_renders_registered_claim_reason() {
        let mut res = Response::new();
        render_service_error(
            &mut res,
            ServiceError::Conflict(
                "approval_required: target List WIP review has no verified approval".to_owned(),
            ),
        );
        assert_eq!(
            res.status_code,
            Some(crate::error::error_http_status(
                arkret_wire::ErrorCode::ClaimRequired
            ))
        );
        let body: serde_json::Value = salvo::test::ResponseExt::take_json(&mut res)
            .await
            .expect("problem body");
        assert_eq!(body["type"], "https://arkret.org/problems/claim_required");
        assert_eq!(body["reason_code"], "approval_required");
    }

    /// `schema_violation` is registered at 422 (`error-code-registry.json`);
    /// the authority lane must not render it as a 400.
    #[tokio::test]
    async fn schema_violation_renders_at_its_registry_status() {
        let mut res = Response::new();
        render_service_error(
            &mut res,
            ServiceError::SchemaViolation("stream_ref is outside the closed union".to_owned()),
        );
        assert_eq!(res.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
        let body: serde_json::Value = salvo::test::ResponseExt::take_json(&mut res)
            .await
            .expect("problem body");
        assert_eq!(body["status"], 422, "{body}");
        assert_eq!(
            body["type"], "https://arkret.org/problems/schema_violation",
            "{body}"
        );
    }

    #[tokio::test]
    async fn founding_same_key_different_unit_renders_duplicate_conflict() {
        let mut res = Response::new();
        render_service_error(
            &mut res,
            ServiceError::Conflict(
                "duplicate_conflict: the idempotency key already founded another unit".to_owned(),
            ),
        );
        assert_eq!(res.status_code, Some(StatusCode::CONFLICT));
        let body: serde_json::Value = salvo::test::ResponseExt::take_json(&mut res)
            .await
            .expect("problem body");
        assert_eq!(
            body["type"],
            "https://arkret.org/problems/duplicate_conflict"
        );
        assert_eq!(body["status"], 409);
    }

    #[tokio::test]
    async fn precondition_refusals_render_their_registered_identities() {
        use coland_storage::ConflictCode;
        for (code, status, wire_code, reason_code) in [
            (
                ConflictCode::EpochMismatch,
                StatusCode::CONFLICT,
                "epoch_mismatch",
                None,
            ),
            (
                ConflictCode::EpochUpdateRequired,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some("epoch_update_required"),
            ),
            (
                ConflictCode::MlsActivationRequired,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some("mls_activation_required"),
            ),
            (
                ConflictCode::MlsActivationIrreversible,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some("mls_activation_irreversible"),
            ),
            (
                ConflictCode::GovernanceBindingMismatch,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some("governance_binding_mismatch"),
            ),
            (
                ConflictCode::TemporarilyUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                None,
            ),
            (
                ConflictCode::FailedPrecondition,
                StatusCode::CONFLICT,
                "failed_precondition",
                None,
            ),
            (
                ConflictCode::StrandNotActive,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some("strand_not_active"),
            ),
            (
                ConflictCode::StrandNotArchived,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some("strand_not_archived"),
            ),
            (
                ConflictCode::StrandAlreadyTerminal,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some("strand_already_terminal"),
            ),
            (
                ConflictCode::SpaceNotActive,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some("space_not_active"),
            ),
            (
                ConflictCode::SpaceNotArchived,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some("space_not_archived"),
            ),
            (
                ConflictCode::SpaceAlreadyTerminal,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some("space_already_terminal"),
            ),
            (
                ConflictCode::CrossRealmStructuralRelation,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some("cross_realm_structural_relation"),
            ),
            (
                ConflictCode::SpaceHasLiveDependents,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some(arkret_wire::ReasonCode::SPACE_HAS_LIVE_DEPENDENTS),
            ),
            (
                ConflictCode::SpaceParentMismatch,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some(arkret_wire::ReasonCode::SPACE_PARENT_MISMATCH),
            ),
            (
                ConflictCode::SpaceParentUnreadable,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some(arkret_wire::ReasonCode::SPACE_PARENT_UNREADABLE),
            ),
            (
                ConflictCode::SpaceRealmMismatch,
                StatusCode::CONFLICT,
                "failed_precondition",
                Some(arkret_wire::ReasonCode::SPACE_REALM_MISMATCH),
            ),
        ] {
            let mut res = Response::new();
            render_service_error(
                &mut res,
                ServiceError::Conflict(format!("{code}: gate refused")),
            );
            assert_eq!(res.status_code, Some(status), "{code}");
            let body: serde_json::Value = salvo::test::ResponseExt::take_json(&mut res)
                .await
                .expect("problem body");
            assert_eq!(body["status"], status.as_u16(), "{body}");
            assert_eq!(
                body["type"],
                format!("https://arkret.org/problems/{wire_code}"),
                "{body}"
            );
            assert_eq!(body["detail"], "gate refused", "{body}");
            match reason_code {
                Some(reason_code) => assert_eq!(body["reason_code"], reason_code, "{body}"),
                None => assert!(body.get("reason_code").is_none(), "{body}"),
            }
        }
    }

    #[tokio::test]
    async fn call_genesis_noninitial_state_renders_registered_precondition_reason() {
        let mut res = Response::new();
        render_service_error(
            &mut res,
            ServiceError::Conflict(format!(
                "{}: Call genesis cannot enter active",
                coland_storage::ConflictCode::CallStateTransitionInvalid
            )),
        );
        assert_eq!(res.status_code, Some(StatusCode::CONFLICT));
        let problem: arkret_wire::Problem = salvo::test::ResponseExt::take_json(&mut res)
            .await
            .expect("typed Call Problem");
        assert_eq!(problem.status, 409);
        assert_eq!(problem.code(), arkret_wire::ErrorCode::FAILED_PRECONDITION);
        let value = serde_json::to_value(&problem).unwrap();
        assert_eq!(
            value["reason_code"],
            arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID
        );
        assert_eq!(
            value["type"],
            "https://arkret.org/problems/failed_precondition"
        );
    }

    #[tokio::test]
    async fn mounted_authority_reads_gate_before_delegating() {
        let service = crate::service(AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        ));
        let post = |path: &str, operation: &str| {
            TestClient::post(format!("http://server{path}")).add_header(
                "Arkret-Operation",
                operation,
                true,
            )
        };
        let bundle = arkret_wire::ServiceOperationId::OPEN_REALM_AUTHORITY_READ_BUNDLE_V1;
        let scan = arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1;

        // The open bundle needs no session; a body outside the closed
        // request schema never reaches the application port.
        let mut response = post("/_arkret/open/realm-authority/bundle", bundle)
            .json(&serde_json::json!({}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
        let body: serde_json::Value = response.take_json().await.expect("problem body");
        assert_eq!(
            body["type"], "https://arkret.org/problems/schema_violation",
            "{body}"
        );
        let mut response = post("/_arkret/open/realm-authority/bundle", bundle)
            .raw_json("{")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::BAD_REQUEST));
        let body: serde_json::Value = response.take_json().await.expect("problem body");
        assert_eq!(
            body["type"], "https://arkret.org/problems/json_invalid",
            "{body}"
        );

        // The self scan authenticates before it reads the body.
        let mut response = post("/_arkret/self/streams/scan", scan)
            .json(&serde_json::json!({}))
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
        let body: serde_json::Value = response.take_json().await.expect("problem body");
        assert_eq!(
            body["type"], "https://arkret.org/problems/unauthenticated",
            "{body}"
        );

        // The peer scan is selectable (http_core) and authenticates the
        // calling Station before it reads the body: an unsigned request is
        // refused and never reaches the application port.
        let peer_scan = arkret_wire::ServiceOperationId::PEER_COMMITTED_EVENT_READ_SCAN_V1;
        let realm_id = "ak:realm:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0";
        let mut response = post("/_arkret/peer/streams/scan", peer_scan)
            .json(&serde_json::json!({
                "realm_id": realm_id,
                "stream_ref": {"kind": "realm", "realm_id": realm_id},
                "after_position": null,
                "limit": 10,
            }))
            .send(&service)
            .await;
        let status = response.status_code.expect("status");
        let body: serde_json::Value = response.take_json().await.expect("problem body");
        assert!(status.is_client_error(), "{status}: {body}");
        for unreachable in ["unrecognized_endpoint", "unsupported_operation_version"] {
            assert_ne!(
                body["type"],
                format!("https://arkret.org/problems/{unreachable}"),
                "{body}"
            );
        }

        let mut response = post(
            "/_arkret/peer/realm-authority/handoff",
            arkret_wire::ServiceOperationId::PEER_REALM_AUTHORITY_COMMAND_HANDOFF_V1,
        )
        .json(&serde_json::json!({}))
        .send(&service)
        .await;
        assert_eq!(response.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
        let problem: serde_json::Value = response.take_json().await.unwrap();
        assert_eq!(
            problem["type"],
            "https://arkret.org/problems/schema_violation"
        );
        assert!(
            problem["detail"]
                .as_str()
                .unwrap()
                .contains("federation header")
        );
        // The retired resolver is still absent.
        for path in ["/_arkret/peer/streams/resolve"] {
            let response = TestClient::post(format!("http://server{path}"))
                .json(&serde_json::json!({}))
                .send(&service)
                .await;
            assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND), "{path}");
        }
    }
}
