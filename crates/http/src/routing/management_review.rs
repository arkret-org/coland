//! The three registered private management operations; no approval commits an Event.
use arkret_models_integration::management_review::*;
use coland_http::error::AppError;
use coland_http::result::AppResult;
use salvo::oapi::endpoint;
use salvo::prelude::*;

use crate::routing::system::extract::AuthArgs;
use crate::state::AppState;

pub(super) fn router() -> Router {
    Router::with_path("management-reviews")
        .push(Router::with_path("requests").post(request_review))
        .push(Router::with_path("status").post(review_status))
        .push(Router::with_path("decisions").post(decide_review))
}

#[endpoint(
    operation_id = "ak.self.management_review.command.request",
    request_body = ManagementReviewRequestBody,
    tags("management_review")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.management_review.command.request.v1"))]
async fn request_review(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<ManagementReviewResponse> {
    super::authority_commit::no_store(res);
    let state = depot.get_typed::<AppState>().expect("state injected");
    let (caller, session) = review_caller(
        &aa,
        state,
        req,
        arkret_wire::ServiceOperationId::SelfManagementReviewCommandRequestV1,
    )
    .await?;
    let body = read_closed::<ManagementReviewRequestBody>(req).await?;
    body.validate()
        .map_err(|_| AppError::schema_violation("invalid management review request"))?;
    if body.requester_actor_id != caller {
        return Err(AppError::capability_denied(
            "requester differs from authenticated controller",
        ));
    }
    // Preserve an exact accepted outcome before current producer/Policy gates.
    // This authenticated material is Station-private and never caller authority.
    let mut accounts = caller
        .as_account_id()
        .cloned()
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    match state
        .persistence()
        .management_review_material(&caller, &body.request_id, &[])
        .await
    {
        Ok(material) if material.outcome.status == ManagementReviewStatus::Consumed => {
            let original = material.request;
            let outcome = material.outcome;
            if original
                .canonical_intent_digest()
                .map_err(|_| AppError::schema_violation("invalid retained review"))?
                != body
                    .canonical_intent_digest()
                    .map_err(|_| AppError::schema_violation("invalid review request"))?
            {
                return Err(crate::app_error!(
                    DuplicateConflict,
                    "review id is bound to different immutable intent"
                ));
            }
            return Ok(ManagementReviewResponse::Outcome(outcome));
        }
        Ok(material) => accounts.extend(material.accounts),
        Err(coland_storage::PersistenceError::NotFound(_)) => {}
        Err(error) => return Ok(ManagementReviewResponse::Refusal(error.into())),
    }
    // This verifies the original producer. It neither authors nor queues the Event.
    let outcome = async {
        if let Some(account) = state.event_queries().configuration_review_account(&body).await? {
            accounts.insert(account);
        }
        let mut current =
            crate::approval_admission::observe_management_accounts(state, accounts).await?;
        current.applet_event = super::extensions::applet_bridge::prepare_event_current(state,&body.target).await?;
        let producer = match (&body.target, &session) {
            (ManagementReviewTarget::Event { event }, None) if event.kind == arkret_wire::EventKind::RealmActorCreate || (matches!(event.kind, arkret_wire::EventKind::ProfileCreate | arkret_wire::EventKind::ProfileUpdate) && matches!(event.scope_ref, arkret_wire::ScopeRef::RealmControl { .. })) => None,
            (ManagementReviewTarget::Event { event }, None) if event.applet_id.is_some() => {
                let authority=state.persistence().applet_managed_event_producer(event,chrono::Utc::now()).await?
                    .ok_or_else(||coland_services::ServiceError::Conflict("capability_denied: management target has no native Device producer".into()))?;
                if caller!=arkret_wire::ActorId::service(authority.source_service_id.clone()) {
                    return Err(coland_services::ServiceError::Conflict("capability_denied: management requester is not the native Account's Service".into()));
                }
                let material=current.applet_event.as_ref().ok_or_else(||coland_services::ServiceError::Conflict("revision_unavailable: native management resolver material is absent".into()))?;
                Some(coland_storage::SelfProducerCommitGuard::AppletManagedDevice(Box::new(coland_storage::AppletManagedDeviceScopeGuard {
                    authority,effective_scope:event.scope_ref.clone(),service_did_document:material.service_did_document.clone(),
                })))
            }
            (ManagementReviewTarget::Event { event }, Some(session)) => {
                Some(crate::state::verify_self_event_producer(state, session, event).await?)
            }
            _ => {
                return Err(coland_services::ServiceError::protocol(
                    arkret_wire::ErrorCode::CapabilityDenied,
                    "review caller does not match target authority",
                ));
            }
        };
        state
            .persistence()
            .management_review_request(
                &caller,
                &body,
                producer.as_ref(),
                &current,
                chrono::Utc::now(),
            )
            .await
            .map_err(coland_services::ServiceError::from)
    }
    .await;
    Ok(ManagementReviewResponse::from(outcome))
}

#[endpoint(
    operation_id = "ak.self.management_review.read.status",
    request_body = ManagementReviewLookupRequestBody,
    tags("management_review")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.management_review.read.status.v1"))]
async fn review_status(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<ManagementReviewResponse> {
    super::authority_commit::no_store(res);
    let state = depot.get_typed::<AppState>().expect("state injected");
    let (caller, _) = review_caller(
        &aa,
        state,
        req,
        arkret_wire::ServiceOperationId::SelfManagementReviewReadStatusV1,
    )
    .await?;
    let body = read_closed::<ManagementReviewLookupRequestBody>(req).await?;
    let outcome = async {
        let material = state
            .persistence()
            .management_review_material(&caller, &body.request_id, &[])
            .await
            .map_err(coland_services::ServiceError::from)?;
        let mut current = crate::approval_admission::observe_management_accounts(
            state,
            material.accounts.into_iter().collect(),
        )
        .await?;
        if matches!(
            material.outcome.status,
            ManagementReviewStatus::Pending | ManagementReviewStatus::Approved
        ) && chrono::Utc::now() < material.outcome.expires_at
        {
            current.applet_event = super::extensions::applet_bridge::prepare_event_current(
                state,
                &material.request.target,
            )
            .await?;
        }
        state
            .persistence()
            .management_review_status(&caller, &body, &current, chrono::Utc::now())
            .await
            .map_err(coland_services::ServiceError::from)
    }
    .await;
    Ok(ManagementReviewResponse::from(outcome))
}

#[endpoint(
    operation_id = "ak.self.management_review.command.decide",
    request_body = ManagementReviewDecisionRequestBody,
    tags("management_review")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.management_review.command.decide.v1"))]
async fn decide_review(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
) -> AppResult<ManagementReviewResponse> {
    super::authority_commit::no_store(res);
    let state = depot.get_typed::<AppState>().expect("state injected");
    let (caller, _) = review_caller(
        &aa,
        state,
        req,
        arkret_wire::ServiceOperationId::SelfManagementReviewCommandDecideV1,
    )
    .await?;
    let body = read_closed::<ManagementReviewDecisionRequestBody>(req).await?;
    body.validate()
        .map_err(|_| AppError::schema_violation("invalid management review decision"))?;
    if caller.as_account_id().is_none() && body.decision != ManagementReviewDecision::Cancel {
        return Err(AppError::capability_denied(
            "a Service may only cancel its own review",
        ));
    }
    let outcome = async {
        let material = state
            .persistence()
            .management_review_material(&caller, &body.request_id, &body.approval_signatures)
            .await
            .map_err(coland_services::ServiceError::from)?;
        let mut current_accounts = crate::approval_admission::observe_management_accounts(
            state,
            material.accounts.into_iter().collect(),
        )
        .await?;
        if matches!(
            material.outcome.status,
            ManagementReviewStatus::Pending | ManagementReviewStatus::Approved
        ) && chrono::Utc::now() < material.outcome.expires_at
        {
            current_accounts.applet_event =
                super::extensions::applet_bridge::prepare_event_current(
                    state,
                    &material.request.target,
                )
                .await?;
        }
        let methods = if body.decision == ManagementReviewDecision::Approve {
            let mut signatures = material.outcome.approval_signatures;
            for signature in &body.approval_signatures {
                if !signatures.contains(signature) {
                    signatures.push(signature.clone());
                }
            }
            crate::approval_admission::prepare_approval_methods(
                state,
                &signatures,
                chrono::Utc::now(),
            )
            .await?
        } else {
            Vec::new()
        };
        state
            .persistence()
            .management_review_decide(
                &caller,
                &body,
                &methods,
                &current_accounts,
                chrono::Utc::now(),
            )
            .await
            .map_err(coland_services::ServiceError::from)
    }
    .await;
    Ok(ManagementReviewResponse::from(outcome))
}

async fn review_caller(
    aa: &AuthArgs,
    state: &AppState,
    req: &mut Request,
    operation: arkret_wire::ServiceOperationId,
) -> Result<
    (
        arkret_wire::ActorId,
        Option<coland_services::identity::SessionIdentityState>,
    ),
    AppError,
> {
    if req.headers().get_all("arkret-operation").iter().count() != 1
        || req
            .headers()
            .get("arkret-operation")
            .and_then(|value| value.to_str().ok())
            != Some(operation.as_str())
    {
        return Err(AppError::capability_denied(
            "management operation does not match this route",
        ));
    }
    if req.headers().contains_key("source-service-id") {
        let carrier =
            crate::routing::extensions::applet_bridge::verify_self_control_service(state, req)
                .await?;
        Ok((arkret_wire::ActorId::service(carrier.service_id), None))
    } else {
        let session = aa.authenticated_session(state, req).await?;
        let caller =
            crate::routing::identity::session_actor::validated_session_actor(state, &session)
                .await?;
        Ok((caller, Some(session)))
    }
}

async fn read_closed<T: serde::de::DeserializeOwned>(req: &mut Request) -> Result<T, AppError> {
    let bytes = req
        .payload()
        .await
        .map_err(|_| AppError::json_invalid("invalid management review request"))?;
    serde_json::from_slice(bytes).map_err(|error| {
        if error.is_data() {
            AppError::schema_violation("invalid management review request")
        } else {
            AppError::json_invalid("invalid management review request")
        }
    })
}

/// Preserve the authority service's registered refusal renderer while exposing
/// only the original SDK success carrier in generated API documentation.
enum ManagementReviewResponse {
    Outcome(ManagementReviewOutcome),
    Refusal(coland_services::ServiceError),
}
impl From<coland_services::ServiceResult<ManagementReviewOutcome>> for ManagementReviewResponse {
    fn from(result: coland_services::ServiceResult<ManagementReviewOutcome>) -> Self {
        match result {
            Ok(value) => Self::Outcome(value),
            Err(error) => Self::Refusal(error),
        }
    }
}
impl salvo::oapi::ToResponses for ManagementReviewResponse {
    fn to_responses(components: &mut salvo::oapi::Components) -> salvo::oapi::Responses {
        <Json<ManagementReviewOutcome> as salvo::oapi::ToResponses>::to_responses(components)
    }
}
impl salvo::oapi::EndpointOutRegister for ManagementReviewResponse {
    fn register(components: &mut salvo::oapi::Components, operation: &mut salvo::oapi::Operation) {
        <Json<ManagementReviewOutcome> as salvo::oapi::EndpointOutRegister>::register(
            components, operation,
        );
    }
}
impl salvo::Scribe for ManagementReviewResponse {
    fn render(self, res: &mut Response) {
        match self {
            Self::Outcome(value) => res.render(Json(value)),
            Self::Refusal(error) => super::authority_commit::render_service_error(res, error),
        }
    }
}
