//! Complete native MLS retry identity, shared by HTTP recovery and its Event transaction.
use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitRequestBody, SelfAuthoritySubmitResponseBody,
};
use arkret_wire::{ActorId, AuthoritySubmitResponseBody, RealmCommit, ServiceOperationId};
use coland_services::{ServiceError, ServiceResult};

use super::AppState;

#[derive(Clone)]
pub(in crate::state) struct NativeMlsRequest {
    request: Box<SelfAuthoritySubmitRequestBody>,
    actor: ActorId,
    key: String,
    hash: String,
}

impl NativeMlsRequest {
    #[inline(never)]
    pub(in crate::state) fn from_request(
        request: &SelfAuthoritySubmitRequestBody,
    ) -> ServiceResult<Option<Self>> {
        let SelfAuthoritySubmitRequestBody::MlsCommit(submission) = request else {
            return Ok(None);
        };
        let bytes = arkret_canonical::canonical_json_bytes(request).map_err(schema)?;
        Ok(Some(Self {
            request: Box::new(request.clone()),
            actor: submission.commit_event.actor_id.clone(),
            key: submission.idempotency_key.as_uuid().to_string(),
            hash: arkret_canonical::sha256_digest(&bytes),
        }))
    }

    pub(in crate::state) async fn replay(
        &self,
        state: &AppState,
    ) -> ServiceResult<Option<SelfAuthoritySubmitResponseBody>> {
        let Some(record) = state
            .jobs()
            .scoped_idempotency_record(
                &self.actor,
                ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                &self.key,
            )
            .await?
        else {
            return Ok(None);
        };
        if record.request_hash != self.hash {
            return Err(ServiceError::Conflict(
                "duplicate_conflict: native MLS retry key binds a different complete unit".into(),
            ));
        }
        let outcome: SelfAuthoritySubmitResponseBody =
            serde_json::from_value(record.response_body).map_err(schema)?;
        outcome
            .validate_for_request(&self.request)
            .map_err(schema)?;
        Ok(Some(outcome))
    }

    pub(in crate::state) fn response(
        &self,
        outcome: &AuthoritySubmitResponseBody,
    ) -> ServiceResult<coland_services::events::IdempotentResponse> {
        let now = chrono::Utc::now();
        Ok(coland_services::events::IdempotentResponse {
            authenticated_actor: self.actor.clone(),
            operation_id: ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1.to_owned(),
            key: self.key.clone(),
            request_hash: self.hash.clone(),
            status: 200,
            body: serde_json::to_value(SelfAuthoritySubmitResponseBody::Ordinary(outcome.clone()))
                .map_err(schema)?,
            created_at: now,
            expires_at: now + chrono::Duration::days(30),
        })
    }

    pub(in crate::state) fn refusal_record(
        &self,
        reason: &str,
    ) -> ServiceResult<coland_storage::IdempotencyRecord> {
        let response = self.response(&AuthoritySubmitResponseBody::Rejected {
            status: arkret_wire::AuthorityRejectionStatus::Rejected,
            reason_code: reason.to_owned(),
        })?;
        Ok(coland_storage::IdempotencyRecord {
            authenticated_actor: response.authenticated_actor,
            operation_id: response.operation_id,
            idempotency_key: response.key,
            request_hash: response.request_hash,
            response_status: response.status,
            response_body: response.body,
            created_at: response.created_at,
            expires_at: response.expires_at,
        })
    }

    pub(in crate::state) fn accepted_response(
        &self,
        commit: &RealmCommit,
    ) -> ServiceResult<coland_services::events::IdempotentResponse> {
        self.response(&AuthoritySubmitResponseBody::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Committed,
            commit: commit.clone(),
        })
    }

    pub(in crate::state) async fn retain_outcome(
        &self,
        state: &AppState,
        outcome: SelfAuthoritySubmitResponseBody,
    ) -> ServiceResult<SelfAuthoritySubmitResponseBody> {
        // A racing writer can have installed the first result while this
        // attempt recovered the exact Event. Always compare the full unit.
        if let Some(original) = self.replay(state).await? {
            return Ok(original);
        }
        if !matches!(
            &outcome,
            SelfAuthoritySubmitResponseBody::Ordinary(
                AuthoritySubmitResponseBody::Accepted { .. }
                    | AuthoritySubmitResponseBody::Rejected { .. }
            )
        ) {
            return Ok(outcome);
        }
        let SelfAuthoritySubmitResponseBody::Ordinary(ref ordinary) = outcome else {
            unreachable!()
        };
        let response = self.response(ordinary)?;
        state
            .jobs()
            .store_idempotency_record(coland_storage::IdempotencyRecord {
                authenticated_actor: response.authenticated_actor,
                operation_id: response.operation_id,
                idempotency_key: response.key,
                request_hash: response.request_hash,
                response_status: response.status,
                response_body: response.body,
                created_at: response.created_at,
                expires_at: response.expires_at,
            })
            .await?;
        self.replay(state)
            .await?
            .ok_or_else(|| ServiceError::Internal("native MLS retry outcome is unavailable".into()))
    }
}

fn schema(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::SchemaViolation(error.to_string())
}
