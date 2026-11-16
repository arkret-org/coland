//! Complete MLS retry identity, shared by HTTP recovery and its Event transaction.
use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitRequestBody, SelfAuthoritySubmitResponseBody,
};
use arkret_wire::{ActorId, AuthoritySubmitResponseBody, RealmCommit, ServiceOperationId};
use coland_services::{ServiceError, ServiceResult};

use super::AppState;

#[derive(Clone)]
pub(in crate::state) struct MlsRequest {
    request: Box<SelfAuthoritySubmitRequestBody>,
    actor: ActorId,
    key: String,
    hash: String,
}

impl MlsRequest {
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
            actor: submission.commit_event.actual_signer().clone(),
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
                "duplicate_conflict: MLS retry key binds a different complete unit".into(),
            ));
        }
        let outcome: SelfAuthoritySubmitResponseBody =
            serde_json::from_value(record.response_body).map_err(schema)?;
        self.validate_outcome(&outcome)?;
        Ok(Some(outcome))
    }

    fn validate_outcome(&self, outcome: &SelfAuthoritySubmitResponseBody) -> ServiceResult<()> {
        outcome
            .validate_for_request(&self.request)
            .map_err(schema)?;
        if let (
            SelfAuthoritySubmitRequestBody::MlsCommit(request),
            SelfAuthoritySubmitResponseBody::Ordinary(outcome),
        ) = (self.request.as_ref(), outcome)
        {
            outcome
                .validate_for_request(&arkret_wire::AuthoritySubmitRequestBody::MlsCommit(
                    request.clone(),
                ))
                .map_err(schema)?;
        }
        Ok(())
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
        self.validate_outcome(&outcome)?;
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
        let stored = state
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
            .await;
        match stored {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.conflict_code(),
                    Some(
                        coland_storage::ConflictCode::AccountErased
                            | coland_storage::ConflictCode::AccountDeactivated
                    )
                ) =>
            {
                return Ok(outcome);
            }
            Err(error) => return Err(error),
        }
        // H's optional private mirror is not the governing source ledger.
        // A terminal owner may have erased/skipped it after G really answered.
        Ok(self.replay(state).await?.unwrap_or(outcome))
    }
}

fn schema(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::SchemaViolation(error.to_string())
}

#[cfg(test)]
mod tests {
    use arkret_models_crypto::{MlsCommitPayload, MlsGovernanceBindingPayload};
    use arkret_wire::{
        AccountId, ActorId, AuthoredEvent, BlobRef, DidCoreId, DidUrl, Event, EventId, EventKind,
        MlsCommitSubmission, RealmId, ScopeRef,
    };

    use super::*;

    fn account(principal: &str) -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(format!("ak:did_core:web:{principal}.example")).unwrap(),
            DidCoreId::new("ak:did_core:web:origin.example").unwrap(),
        ))
    }

    // This is an exact SDK carrier/producer identity test, not a native PCR,
    // Agent delegation or authority-admission fixture. Those independent gates
    // remain required and are not widened by choosing a retry namespace.
    fn attributed_request(agent_name: &str, seed: u8) -> SelfAuthoritySubmitRequestBody {
        let controller = account("controller");
        let executor = account(agent_name);
        let method = DidUrl::new(format!("did:web:{agent_name}.example#runtime")).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let base = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [91; 32]);
        let realm = RealmId::from_event_id(&base);
        let scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let identity = arkret_mls::ArkretMlsIdentity::new_agent(
            executor.clone(),
            method.clone(),
            base.clone(),
            arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
        )
        .unwrap();
        let genesis = MlsGovernanceBindingPayload::realm(realm.clone(), None, 0, 0, 0).unwrap();
        let mut group = identity
            .create_group_with_governance_binding(&scope, &genesis)
            .unwrap();
        let binding =
            MlsGovernanceBindingPayload::realm(realm.clone(), Some(base.clone()), 0, 1, 0).unwrap();
        let commit = group
            .self_update_commit_with_governance_binding(&binding)
            .unwrap();
        let (info, tree) = group
            .pending_public_group_state_bytes(&commit, &binding)
            .unwrap();
        let payload = MlsCommitPayload::new(
            base.clone(),
            0,
            &commit,
            binding,
            BlobRef::new(format!(
                "ak:blob:{}",
                arkret_canonical::sha256_digest(&info)
            ))
            .unwrap(),
            BlobRef::new(format!(
                "ak:blob:{}",
                arkret_canonical::sha256_digest(&tree)
            ))
            .unwrap(),
        )
        .unwrap();
        let serde_json::Value::Object(payload) = serde_json::to_value(payload).unwrap() else {
            unreachable!("typed MLS payload is an object");
        };
        let event = Event {
            event_id: base.clone(),
            kind: EventKind::MlsCommit,
            realm_id: realm,
            scope_ref: scope,
            actor_id: controller,
            executed_by: Some(executor),
            authorization_ref: Some(base.into()),
            applet_id: None,
            external_ref: None,
            created_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            semantic_refs: Vec::new(),
            payload: payload.into_iter().collect(),
            producer_proof: None,
        };
        let mut authored =
            AuthoredEvent::finalize_with_digest_suite(event, arkret_canonical::DigestSuite::Sha256)
                .unwrap();
        let signer = arkret_signatures::Ed25519DetachedJwsSigner::new(key, method.as_str());
        arkret_signatures::sign_event(
            &mut authored,
            &signer,
            arkret_signatures::SignEventOptions::new(),
        )
        .unwrap();
        let submission = MlsCommitSubmission {
            commit_event: authored.into_event(),
            welcomes: Vec::new(),
            idempotency_key: serde_json::from_value(serde_json::json!(
                "01904100-0000-7000-8000-000000000093"
            ))
            .unwrap(),
            recovery_source: None,
        };
        submission.validate().unwrap();
        SelfAuthoritySubmitRequestBody::MlsCommit(submission)
    }

    #[test]
    fn retry_namespace_uses_actual_agent_signer_not_common_attributed_controller() {
        let first = attributed_request("agent-one", 94);
        let second = attributed_request("agent-two", 95);
        let first = MlsRequest::from_request(&first).unwrap().unwrap();
        let second = MlsRequest::from_request(&second).unwrap().unwrap();
        assert_eq!(first.actor, account("agent-one"));
        assert_eq!(second.actor, account("agent-two"));
        assert_ne!(first.actor, account("controller"));
        assert_ne!(first.actor, second.actor);
        assert_eq!(first.key, second.key);
        let response = first
            .response(&AuthoritySubmitResponseBody::Rejected {
                status: arkret_wire::AuthorityRejectionStatus::Rejected,
                reason_code: "governance_binding_mismatch".into(),
            })
            .unwrap();
        assert_eq!(response.authenticated_actor, account("agent-one"));
    }
}
