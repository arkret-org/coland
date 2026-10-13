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
    let session = aa.authenticated_session(state, req).await?;
    let caller =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
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
    let mut accounts = std::collections::BTreeSet::from([
        caller
            .as_account_id()
            .ok_or_else(|| AppError::capability_denied("human review caller required"))?
            .clone(),
        body.requester_actor_id
            .as_account_id()
            .ok_or_else(|| AppError::capability_denied("human controller required"))?
            .clone(),
    ]);
    match state
        .persistence()
        .management_review_material(&caller, &body.request_id, &[])
        .await
    {
        Ok(material) if material.outcome.status == ManagementReviewStatus::Consumed => {
            let original = material.request;
            let outcome = material.outcome;
            if arkret_canonical::canonical_sha256(&original)
                .map_err(|_| AppError::schema_violation("invalid retained review"))?
                != arkret_canonical::canonical_sha256(&body)
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
    let ManagementReviewTarget::Event { event } = &body.target else {
        return Err(AppError::unsupported_feature(
            "managed creation review is not implemented",
        ));
    };
    // This verifies the original producer. It neither authors nor queues the Event.
    let outcome = async {
        let current =
            crate::approval_admission::observe_management_accounts(state, accounts).await?;
        let producer = crate::state::verify_self_event_producer(state, &session, event).await?;
        state
            .persistence()
            .management_review_request(&caller, &body, &producer, &current, chrono::Utc::now())
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
    let session = aa.authenticated_session(state, req).await?;
    let caller =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    let body = read_closed::<ManagementReviewLookupRequestBody>(req).await?;
    let outcome = async {
        let material = state
            .persistence()
            .management_review_material(&caller, &body.request_id, &[])
            .await
            .map_err(coland_services::ServiceError::from)?;
        let current = crate::approval_admission::observe_management_accounts(
            state,
            material.accounts.into_iter().collect(),
        )
        .await?;
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
    let session = aa.authenticated_session(state, req).await?;
    let caller =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    let body = read_closed::<ManagementReviewDecisionRequestBody>(req).await?;
    body.validate()
        .map_err(|_| AppError::schema_violation("invalid management review decision"))?;
    let outcome = async {
        let material = state
            .persistence()
            .management_review_material(&caller, &body.request_id, &body.approval_signatures)
            .await
            .map_err(coland_services::ServiceError::from)?;
        let current_accounts = crate::approval_admission::observe_management_accounts(
            state,
            material.accounts.into_iter().collect(),
        )
        .await?;
        let methods = if body.decision == ManagementReviewDecision::Approve {
            let original = material.request;
            let current = material.outcome;
            let ManagementReviewTarget::Event { event } = original.target else {
                return Err(coland_services::ServiceError::protocol(
                    arkret_wire::ErrorCode::UnsupportedFeature,
                    "managed creation review is not implemented",
                ));
            };
            let mut signatures = current.approval_signatures;
            for signature in &body.approval_signatures {
                if !signatures.contains(signature) {
                    signatures.push(signature.clone());
                }
            }
            let submission = arkret_wire::EventAdmissionSubmission {
                event: *event,
                approval_signatures: Some(signatures),
            };
            crate::approval_admission::prepare_event_approvals_with_management_current(
                state,
                &submission,
                chrono::Utc::now(),
                Some(&current_accounts),
            )
            .await?
            .ok_or_else(|| {
                coland_services::ServiceError::protocol(
                    arkret_wire::ErrorCode::SignatureInvalid,
                    "management approval history is unavailable",
                )
            })?
            .methods
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
