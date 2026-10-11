use super::*;

/// Resolve the exact AccountId for a self recovery-policy read. The optional
/// selector is canonical JSON for that same account; principal-only selectors
/// are not accepted.
pub(super) async fn resolve_recovery_read_account(
    aa: &AuthArgs,
    state: &AppState,
    req: &mut Request,
    account_id_param: Option<String>,
) -> Result<arkret_wire::AccountId, AppError> {
    let session = aa.authenticated_session(state, req).await?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let account_id = session_actor.as_account_id().cloned().ok_or_else(|| {
        crate::app_error!(
            CapabilityDenied,
            "recovery policy requires an account actor",
        )
        .with_internal_reason("recovery_account_isolation")
    })?;
    if let Some(requested) = account_id_param.filter(|value| !value.trim().is_empty()) {
        let requested: arkret_wire::AccountId = serde_json::from_str(&requested).map_err(|_| {
            AppError::schema_violation("account_id must be RFC 8785 JCS(AccountId)")
        })?;
        if requested != account_id {
            return Err(crate::app_error!(
                CapabilityDenied,
                "account_id does not match the authenticated account",
            )
            .with_internal_reason("recovery_account_isolation"));
        }
    }
    Ok(account_id)
}

pub(super) fn typed_recovery_policy_summary(
    record: &coland_services::identity::RecoveryPolicyState,
) -> Result<RecoveryPolicySummary, AppError> {
    let policy: RecoveryPolicy = serde_json::from_value(record.raw_payload.clone())
        .map_err(|error| stored_recovery_type_error("policy payload", error))?;
    policy
        .validate_shape()
        .map_err(|error| stored_recovery_type_error("policy methods", error))?;
    Ok(RecoveryPolicySummary {
        policy_id: PolicyId::new(record.policy_id.clone())
            .map_err(|error| stored_recovery_type_error("policy id", error))?,
        account_id: record.account_id.clone(),
        version: u64::from(record.version),
        acceptance_basis_ref: record.acceptance_basis.clone(),
        recovery_policy_ref: None,
        trust_domain: TrustDomainId::new(record.trust_domain.clone())
            .map_err(|error| stored_recovery_type_error("policy trust domain", error))?,
        methods: policy.methods.clone(),
        supersedes_id: record
            .supersedes
            .as_ref()
            .map(|value| PolicyId::new(value.clone()))
            .transpose()
            .map_err(|error| stored_recovery_type_error("superseded policy id", error))?,
        expires_at: record.expires_at,
        issued_at: record.issued_at,
        accepted_at: Some(record.accepted_at),
        policy: Some(
            serde_json::from_value(record.raw_payload.clone())
                .map_err(|error| stored_recovery_type_error("policy payload", error))?,
        ),
    })
}

pub(super) fn recovery_policy_ref_from_summary(
    summary: &RecoveryPolicySummary,
) -> RecoveryPolicyRef {
    summary
        .recovery_policy_ref
        .clone()
        .unwrap_or_else(|| RecoveryPolicyRef {
            policy_id: summary.policy_id.clone(),
            policy_version: summary.version,
        })
}

fn recovery_policy_publish_outcome(
    record: &RecoveryPolicyState,
) -> Result<RecoveryPolicyPublishOutcome, AppError> {
    Ok(RecoveryPolicyPublishOutcome {
        policy_id: PolicyId::new(record.policy_id.clone())
            .map_err(|error| stored_recovery_type_error("policy id", error))?,
        account_id: record.account_id.clone(),
        version: u64::from(record.version),
        acceptance_basis_ref: record.acceptance_basis.clone(),
        accepted_at: record.accepted_at,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.recovery_policy.resource.get",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.recovery_policy.resource.get.v1")
)]
pub(super) async fn recovery_policy_get(
    aa: AuthArgs,
    account_id: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RecoveryPolicyActiveOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let account = resolve_recovery_read_account(&aa, state, req, account_id.into_inner()).await?;
    let active = state
        .recovery_policies()
        .active_policy(&account)
        .await
        .map_err(recovery_service_error)?;
    let active_policy = active
        .as_ref()
        .map(typed_recovery_policy_summary)
        .transpose()?;
    let recovery_policy_ref = active_policy.as_ref().map(recovery_policy_ref_from_summary);
    json_ok(RecoveryPolicyActiveOutcome {
        account_id: Some(account),
        active_policy,
        recovery_policy_ref,
        as_of: active.as_ref().map(|record| record.accepted_at),
        authority_stream_head: None,
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.identity.recovery_policies.get",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.coland.identity.recovery_policies.get")
)]
pub(super) async fn recovery_policies_get(
    aa: AuthArgs,
    account_id: QueryParam<String, false>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ColandRecoveryPoliciesOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let account = resolve_recovery_read_account(&aa, state, req, account_id.into_inner()).await?;
    let policies = state
        .recovery_policies()
        .policy_history(&account)
        .await
        .map_err(recovery_service_error)?;
    let policies = policies
        .iter()
        .map(typed_recovery_policy_summary)
        .collect::<Result<Vec<_>, _>>()?;
    json_ok(ColandRecoveryPoliciesOutcome { policies })
}

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.recovery_policy.command.publish",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.recovery_policy.command.publish.v1")
)]
pub(super) async fn recovery_policy_put(
    aa: AuthArgs,
    body: JsonBody<RecoveryPolicyPublishRequest>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RecoveryPolicyPublishOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let request = body.into_inner();
    request.validate().map_err(|error| {
        AppError::schema_violation(format!("invalid recovery policy publication: {error}"))
    })?;
    let typed_payload = request.payload().map_err(|error| {
        AppError::schema_violation(format!("invalid recovery policy payload: {error}"))
    })?;
    let payload = serde_json::to_value(&typed_payload.value)
        .map_err(|error| AppError::internal(format!("recovery policy serialize: {error}")))?;

    let policy_account = validate_recovery_policy(&payload)?;
    let session_actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    if policy_account
        != *session_actor.as_account_id().ok_or_else(|| {
            crate::app_error!(
                CapabilityDenied,
                "recovery policy requires an account actor",
            )
        })?
        || request.event().actor_id != session_actor
    {
        return Err(crate::app_error!(
            CapabilityDenied,
            "Event actor and recovery policy account must match the authenticated account",
        )
        .with_reason_code("recovery_principal_isolation"));
    }
    if request.submission().approval_signatures.is_some() {
        return Err(AppError::param_invalid(
            "a device-signed recovery policy publication carries no approval signatures",
        ));
    }
    let event = request.event();
    let committed_at = chrono::Utc::now();
    let method = DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    // Signer device, generation, version ratchet, quorum membership and both
    // signatures are decided by the registered PCR unit at the locked cut.
    let transaction = state
        .authority_commits()
        .prepare_self_event_transaction(
            event,
            &state.service_core_id(),
            method,
            state.notary_signing_key().as_ref(),
            committed_at,
        )
        .await
        .map_err(recovery_policy_publication_error)?;
    let outcome = state
        .recovery_policies()
        .commit_publication(coland_storage::RecoveryPolicyPublicationWrite {
            commit: transaction,
            queued_at: committed_at,
        })
        .await
        .map_err(recovery_policy_publication_error)?;
    let record = match outcome {
        coland_storage::RecoveryPolicyPublicationOutcome::Committed(record)
        | coland_storage::RecoveryPolicyPublicationOutcome::Duplicate(record) => record,
    };
    json_ok(recovery_policy_publish_outcome(&record)?)
}

fn recovery_policy_publication_error(error: coland_services::ServiceError) -> AppError {
    use coland_storage::ConflictCode;
    let registered = match error.conflict_code() {
        // §8.1: the signer is not an active current-generation device of
        // this account; the operation has no device-specific code.
        Some(
            ConflictCode::DeviceRevoked
            | ConflictCode::DeviceRevocationPending
            | ConflictCode::DeviceGenerationFenced
            | ConflictCode::DeviceUnauthorized,
        ) => Some(ErrorCode::CapabilityDenied),
        Some(ConflictCode::SignatureInvalid) => Some(ErrorCode::SignatureInvalid),
        Some(ConflictCode::SchemaViolation | ConflictCode::EventIdDigestMismatch) => {
            Some(ErrorCode::SchemaViolation)
        }
        Some(ConflictCode::FailedPrecondition) => Some(ErrorCode::FailedPrecondition),
        Some(ConflictCode::UnsupportedFeature) => Some(ErrorCode::UnsupportedFeature),
        _ => None,
    };
    match registered {
        Some(code) => AppError::from_rejection(code, error.detail()),
        None => recovery_policy_service_error(error),
    }
}
