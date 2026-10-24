//! Account + contact handlers.
//!
//! Surfaces:
//! - `POST /_coland/gate/account/project` — materialize an Account Authority result
//! - `GET  /_arkret/self/account/viewer` — return the authenticated principal's account
//! - `POST /_arkret/self/contacts/request` — open a pending contact relationship
//! - `POST /_arkret/self/contacts/respond` — accept or reject a pending request
//! - `GET  /_arkret/self/contacts` — list contacts visible to the actor
//! - `POST /_arkret/self/direct-conversations/resolve` — resolve/create the canonical 1:1 DM
//!   binding

use std::collections::{BTreeMap, BTreeSet};

use arkret_identifiers::{BlobRef, DeviceId, DidCoreId, EventId, Hash, RealmId, StrandId};
use arkret_models_collaboration::account_operations::{
    AccountUpdateProfileRequestBody, AccountView,
};
use arkret_models_collaboration::agent_operations::AgentLifecycleState;
// `arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy` also
// resolves at the crate root, but the invite-addressing strong type lives under `model`;
// import it via the `model` path to avoid binding the wrong same-named re-export.
use arkret_models_collaboration::contact_operations::{
    ContactAcceptRequestBody, ContactAgentProjection, ContactNextPrepareInput,
    ContactOperationRequestBody, ContactOperationResponseBody, ContactPage, ContactPeer,
    ContactRejectRequestBody, ContactScopeUpdateRequestBody, ContactState,
    ContactTombstoneRequestBody, ContactView, DirectConversationSummary,
    DirectConversationSummaryState,
};
use arkret_models_collaboration::direct_conversation::{
    DirectConversationCoordinates, DirectConversationFoundingInput,
    DirectConversationResolveRequestBody, DirectConversationResolveResponseBody,
    DirectConversationSendBlocker,
};
use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthorityEvidence;
use arkret_models_identity::account::{
    AccountDeviceSummary, AccountRegistrationAudit, AccountRegistrationAuditOutcome,
    AccountRegistrationEvidenceSummary, AccountRegistrationPolicy,
    AccountRegistrationPolicyEvidence, AccountRegistrationRateLimitPolicy,
    AccountUpdateProfileResponseBody,
};
use arkret_models_identity::actor_profile::{AccountMaterializedProfile, ActorProfile};
use arkret_models_identity::actor_profile_operations::{
    ActorProfileResolveFailure, ActorProfileResolveFailureReason, ActorProfileResolveRequestBody,
    ActorProfileResolveResponseBody, ResolvedActorProfile,
};
use arkret_models_identity::{
    DeviceSummaryStatus, DeviceSummaryVerificationState, PrincipalResolutionAuditEvidence,
    PrincipalResolutionAuditRequestBody,
};
use arkret_wire::ActorId;
use coland_contracts::AccountProjectionRequestBody;
use coland_contracts::admin::{
    AccountLocalpartAddRequestBody, AccountLocalpartListOutcome, AccountLocalpartMutationOutcome,
    AccountLocalpartView,
};
use coland_http::error::AppError;
use coland_services::identity::{
    AccountLifecycleState, AccountLocalpartState as AccountLocalpartRecord,
    AccountProfileState as AccountRecord, AgentPairingState, ContactRecord, DeviceIdentity,
    DirectConversationBindingRecord, SessionIdentityState as SessionRecord,
};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use self::social::direct::direct_founder_for_pair;
use super::auth::{
    purge_device_delivery_state, revoke_devices_for_actor, revoke_sessions_for_actor,
};
use super::did::require_embedded_webvh_registration_bearer;
use super::{AuthArgs, append_audit_log, bearer_token, now, sha256_hex, validate_did};
use crate::routing::validate_device_id;
use crate::state::AppState;
use crate::wire::ColandAccountRegisterOutcome;

/// Deployment-local Station projection result. The Account
/// Authority owns `AccountRegisterResponseBody` and its signed binding receipt;
/// this internal edge only confirms the durable local projection.
#[derive(Debug, Serialize, salvo::oapi::ToSchema)]
struct AccountProjectionRegisterOutcome {
    principal_id: DidCoreId,
    state: AccountStatus,
    #[salvo(schema(value_type = serde_json::Value))]
    devices: Vec<AccountDeviceSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[salvo(schema(value_type = Option<serde_json::Value>))]
    primary_handle_claim: Option<arkret_models_identity::HandleClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[salvo(schema(value_type = Option<serde_json::Value>))]
    profile: Option<ActorProfile>,
    registration_audit: AccountRegistrationAudit,
}

pub(crate) async fn record_handle_release(
    state: &AppState,
    localpart: &str,
) -> coland_services::ServiceResult<()> {
    let released_at = chrono::Utc::now();
    state
        .identities()
        .record_handle_release(localpart, released_at)
        .await?;
    Ok(())
}

/// The account's Station-signed primary handle claim, re-derived on
/// demand from the primary `account_localparts` row. `None` means the account
/// has no published localpart binding, so the client renders "not published".
async fn account_primary_handle_claim(state: &AppState, account: &AccountRecord) -> Option<Value> {
    account_primary_handle_claim_for(state, account, state.service_id().as_str()).await
}

/// Re-derive `account`'s Station-signed primary handle claim
/// bound to `audience`. `None` when the account has no published localpart
/// binding, so the client renders "not published".
pub(crate) async fn account_primary_handle_claim_for(
    state: &AppState,
    account: &AccountRecord,
    audience: &str,
) -> Option<Value> {
    if account.localpart.is_empty() {
        return None;
    }
    match crate::routing::spaces::directory::signed_handle_claim_value(
        state,
        &account.handle(),
        account.principal_id.as_str(),
        audience,
    )
    .await
    {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(%error, principal_id = %account.principal_id, "failed to derive primary handle claim");
            None
        }
    }
}

use crate::{JsonResult, json_ok};

mod current_principal;
mod social;
#[cfg(test)]
pub(crate) use social::direct_binding_matches_projection;
use social::*;
pub(crate) use social::{
    accepted_contact_for_pair, contact_assertion_signer, contact_delivery_address,
    contact_detached_jws, materialize_contact_completions, validate_request_receipt_cryptography,
    verify_contact_service_signature_bytes, verify_contact_service_signature_bytes_at,
};
pub(crate) mod lifecycle;
// Re-export the lifecycle surface used by sibling routing modules.
pub(crate) use lifecycle::{AccountLifecycleChange, set_account_lifecycle_state};

/// Deployment-private Account Authority projection edge. The canonical
/// `ak.gate.account.command.register.v1` operation is owned by the Account
/// Authority and must never be shadowed by this Station materializer.
pub(super) fn local_gate_router() -> Router {
    Router::with_path("account").push(Router::with_path("project").post(project_account))
}

pub(super) fn protocol_router() -> Router {
    Router::new()
        .push(
            Router::with_path("account")
                .push(Router::with_path("viewer").get(account_viewer))
                .push(Router::with_path("current-principal").post(current_principal::resolve))
                // spec `events_sync` surface group (core tier) binds
                // `ak.self.account.command.update_profile.v1` to POST
                // /_arkret/self/account/profile; describe advertises it, so it MUST
                // resolve on the protocol surface.
                .push(Router::with_path("profile").post(update_profile)),
        )
        .push(contact_routes())
        .push(direct_conversation_routes())
        .push(Router::with_path("actor-profiles/query").post(resolve_actor_profiles))
        .push(
            Router::with_path("identity/resolution-audit/query")
                .post(read_principal_resolution_audit),
        )
        .push(
            Router::with_path("invite-receive-policy")
                .get(get_invite_receive_policy)
                .put(set_invite_receive_policy),
        )
}

pub(in crate::routing) fn local_router() -> Router {
    Router::new().push(
        Router::with_path("account")
            .push(Router::with_path("register").post(local_account_register))
            .push(Router::with_path("me").get(local_account_me)),
    )
}

pub(in crate::routing) fn local_service_router() -> Router {
    Router::with_path(coland_contracts::ACCOUNT_LOCALPARTS_ROUTE)
        .get(list_account_localparts)
        .post(add_account_localpart)
}

fn contact_routes() -> Router {
    Router::with_path("contacts")
        .get(list_contacts)
        .push(Router::with_path("request").post(contact_request))
        .push(Router::with_path("respond").post(contact_respond))
        .push(Router::with_path("reject").post(contact_reject))
        .push(Router::with_path("scope-update").post(contact_scope_update))
        .push(Router::with_path("tombstone").post(contact_tombstone))
}

fn direct_conversation_routes() -> Router {
    Router::with_path("direct-conversations")
        .push(Router::with_path("resolve").post(direct_conversation_resolve))
}

#[derive(Clone, Debug, Deserialize, salvo::oapi::ToSchema)]
#[serde(deny_unknown_fields)]
struct LocalAccountRegisterRequestBody {
    pub did: String,
    pub handle: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
}

fn require_account_localparts_bearer(state: &AppState, req: &Request) -> Result<(), AppError> {
    let Some(expected) = state
        .config()
        .embedded_webvh_registration_bearer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "account localparts sync requires COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
        ));
    };
    let Some(provided) = bearer_token(req)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(AppError::unauthenticated(
            "account localparts sync requires Authorization: Bearer <token>",
        ));
    };
    if sha256_hex(provided.as_bytes()) != sha256_hex(expected.as_bytes()) {
        return Err(AppError::unauthenticated(
            "invalid account localparts sync bearer",
        ));
    }
    Ok(())
}

fn account_localpart_view(record: AccountLocalpartRecord) -> AccountLocalpartView {
    AccountLocalpartView {
        id: record.id,
        localpart: record.localpart,
        is_primary: record.is_primary,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn normalize_account_localpart_for_request(localpart: &str) -> Result<String, AppError> {
    let localpart = localpart.trim();
    let localpart = localpart.strip_prefix('@').unwrap_or(localpart);
    if localpart.is_empty() || localpart.contains(':') || localpart.contains('@') {
        return Err(AppError::param_invalid(
            "localpart must be a bare handle localpart",
        ));
    }
    arkret_wire::string_profiles::prepare_handle_localpart(localpart)
        .map_err(|_| AppError::param_invalid("localpart is not a valid handle localpart"))
}

fn account_core_id_from_path(value: String) -> Result<DidCoreId, AppError> {
    DidCoreId::new(value).map_err(|_| AppError::param_invalid("invalid account core id"))
}

fn localpart_persistence_error(error: coland_services::ServiceError) -> AppError {
    if error.is_not_found() {
        AppError::not_found(error.detail())
    } else if error.is_conflict_kind() {
        crate::app_error!(DuplicateConflict, error.detail(),)
    } else {
        AppError::internal(error.to_string())
    }
}

async fn local_account_pk(
    state: &AppState,
    account_principal_id: &DidCoreId,
) -> Result<coland_storage::AccountPk, AppError> {
    state
        .identities()
        .account(&arkret_wire::AccountId::new(
            account_principal_id.clone(),
            state.service_core_id().clone(),
        ))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .map(|account| account.pk)
        .ok_or_else(|| AppError::not_found("account not found"))
}

fn account_registration_policy_snapshot(state: &AppState) -> AccountRegistrationPolicy {
    state.account_registration_policy()
}

fn account_registration_policy_digest(
    policy: &AccountRegistrationPolicy,
) -> Result<Hash, AppError> {
    let digest = arkret_canonical::canonical_sha256(policy)
        .map_err(|error| AppError::internal(format!("registration policy digest: {error}")))?;
    Hash::new(digest).map_err(|error| {
        AppError::internal(format!("registration policy digest is invalid: {error}"))
    })
}

fn account_registration_evidence_summary(
    evidence: Option<&AccountRegistrationPolicyEvidence>,
) -> AccountRegistrationEvidenceSummary {
    AccountRegistrationEvidenceSummary {
        verification_code_present: evidence
            .and_then(|value| value.verification_code.as_deref())
            .is_some_and(|value| !value.trim().is_empty()),
        invitation_token_present: evidence
            .and_then(|value| value.invitation_token.as_deref())
            .is_some_and(|value| !value.trim().is_empty()),
        organization: evidence
            .and_then(|value| value.organization.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
    }
}

fn account_registration_audit(
    policy: &AccountRegistrationPolicy,
    evidence: Option<&AccountRegistrationPolicyEvidence>,
    outcome: AccountRegistrationAuditOutcome,
    retry_after_ms: Option<u64>,
) -> Result<AccountRegistrationAudit, AppError> {
    Ok(AccountRegistrationAudit {
        outcome,
        policy_digest: account_registration_policy_digest(policy)?,
        evidence: account_registration_evidence_summary(evidence),
        retry_after_ms,
    })
}

async fn append_account_registration_audit(
    state: &AppState,
    did: &str,
    handle: Option<&str>,
    audit: &AccountRegistrationAudit,
) {
    append_audit_log(
        state,
        Some(did),
        "account.register",
        json!({
            "operation_contract": arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_REGISTER_V1,
            "principal_id": did,
            "handle_requested": handle,
            "via": "gate",
            "registration_audit": audit,
        }),
        audit.outcome.as_str(),
    )
    .await;
}

async fn reject_account_registration(
    state: &AppState,
    did: &str,
    handle: Option<&str>,
    audit: AccountRegistrationAudit,
    code: coland_http::error::ErrorCode,
    message: &'static str,
) -> AppError {
    append_account_registration_audit(state, did, handle, &audit).await;
    AppError::from_rejection(code, message).with_reason_detail(audit.outcome.as_str())
}

fn digest_registration_secret(value: &str) -> Result<Hash, AppError> {
    Hash::new(arkret_canonical::sha256_digest(value.trim().as_bytes()))
        .map_err(|error| AppError::internal(format!("registration secret digest: {error}")))
}

fn evidence_secret_matches(
    value: Option<&str>,
    accepted_digests: &[Hash],
) -> Result<bool, AppError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(false);
    };
    if accepted_digests.is_empty() {
        return Ok(true);
    }
    let digest = digest_registration_secret(value)?;
    Ok(accepted_digests.iter().any(|accepted| accepted == &digest))
}

fn normalized_registration_policy_label(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn did_host_candidate(did: &str) -> Option<String> {
    did_webvh_host_candidate(did)
}

fn did_webvh_host_candidate(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:webvh:")?;
    let mut parts = rest.split(':');
    let scid = parts.next()?;
    let host = parts.next()?;
    if scid.is_empty() || host.is_empty() {
        return None;
    }
    let host = host
        .split("%3A")
        .next()
        .unwrap_or(host)
        .split("%3a")
        .next()
        .unwrap_or(host);
    Some(normalized_registration_policy_label(host))
}

fn organization_allowed(
    did: &str,
    policy: &AccountRegistrationPolicy,
    evidence: Option<&AccountRegistrationPolicyEvidence>,
) -> bool {
    if policy.organization_allowlist.is_empty() {
        return true;
    }
    let mut candidates = Vec::new();
    if let Some(organization) = evidence.and_then(|value| value.organization.as_deref()) {
        candidates.push(normalized_registration_policy_label(organization));
    }
    if let Some(host) = did_host_candidate(did) {
        candidates.push(host);
    }
    policy.organization_allowlist.iter().any(|allowed| {
        let allowed = normalized_registration_policy_label(allowed);
        candidates
            .iter()
            .any(|candidate| candidate == &allowed || candidate.ends_with(&format!(".{allowed}")))
    })
}

fn account_registration_retry_after_ms(
    state: &AppState,
    did: &str,
    rate_limit: Option<&AccountRegistrationRateLimitPolicy>,
) -> Option<u64> {
    let rate_limit = rate_limit?;
    if rate_limit.max_attempt_count == 0 || rate_limit.window_seconds == 0 {
        return Some(0);
    }
    state.identities().account_registration_retry_after_ms(
        did,
        rate_limit.max_attempt_count,
        rate_limit.window_seconds,
        now(),
    )
}

async fn enforce_account_registration_policy(
    state: &AppState,
    principal_id: &str,
    did: &str,
    handle: Option<&str>,
    evidence: Option<&AccountRegistrationPolicyEvidence>,
) -> Result<AccountRegistrationAudit, AppError> {
    let policy = account_registration_policy_snapshot(state);
    if !policy.enabled {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::RegistrationClosed,
            None,
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            coland_http::error::ErrorCode::FailedPrecondition,
            "account registration is closed",
        )
        .await);
    }
    if let Some(retry_after_ms) =
        account_registration_retry_after_ms(state, principal_id, policy.rate_limit.as_ref())
    {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::RateLimited,
            Some(retry_after_ms),
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            coland_http::error::ErrorCode::RateLimited,
            "account registration rate limit exceeded",
        )
        .await);
    }
    let verification_code = evidence.and_then(|value| value.verification_code.as_deref());
    if policy.verification_code.required
        && verification_code
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::VerificationCodeRequired,
            None,
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            coland_http::error::ErrorCode::FailedPrecondition,
            "registration verification code is required",
        )
        .await);
    }
    if policy.verification_code.required
        && let Some(code_digest) = policy.verification_code.code_digest.as_ref()
        && !evidence_secret_matches(verification_code, std::slice::from_ref(code_digest))?
    {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::VerificationCodeInvalid,
            None,
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            coland_http::error::ErrorCode::FailedPrecondition,
            "registration verification code is invalid",
        )
        .await);
    }
    if !organization_allowed(did, &policy, evidence) {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::OrganizationNotAllowed,
            None,
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            coland_http::error::ErrorCode::FailedPrecondition,
            "principal is not allowed by the registration organization policy",
        )
        .await);
    }
    let invitation_token = evidence.and_then(|value| value.invitation_token.as_deref());
    if policy.invitation.required
        && invitation_token
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::InvitationRequired,
            None,
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            coland_http::error::ErrorCode::FailedPrecondition,
            "registration invitation token is required",
        )
        .await);
    }
    if policy.invitation.required
        && !evidence_secret_matches(invitation_token, &policy.invitation.token_digests)?
    {
        let audit = account_registration_audit(
            &policy,
            evidence,
            AccountRegistrationAuditOutcome::InvitationInvalid,
            None,
        )?;
        return Err(reject_account_registration(
            state,
            principal_id,
            handle,
            audit,
            coland_http::error::ErrorCode::FailedPrecondition,
            "registration invitation token is invalid",
        )
        .await);
    }
    account_registration_audit(
        &policy,
        evidence,
        AccountRegistrationAuditOutcome::Accepted,
        None,
    )
}


async fn agent_direct_authorization_basis(
    state: &AppState,
    controller: &str,
    agent_id: &str,
) -> Result<Option<arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis>, AppError>{
    let Some(record) = state
        .agent_pairings()
        .agent(agent_id)
        .await
        .map_err(|error| AppError::internal(format!("Agent lookup failed: {error}")))?
    else {
        return Ok(None);
    };
    if record.controller_principal_id != controller {
        return Ok(None);
    }
    let unavailable = |detail| {
        direct_resolve_precondition(
            arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
            "direct conversation is unavailable",
        )
        .with_private_detail(detail)
    };
    if record.state != AgentLifecycleState::Active {
        return Err(unavailable(format!(
            "owned Agent is not active: agent_id={agent_id}, state={}",
            record.state.as_wire_str()
        )));
    }
    if let Err(error) = crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        now(),
    )
    .await
    {
        return Err(unavailable(format!(
            "owned-Agent controller binding validation failed: agent_id={agent_id}, controller={controller}, error={error}"
        )));
    }
    agent_direct_authorization_basis_from_record(&record)
        .ok_or_else(|| {
            unavailable(format!(
                "owned-Agent authorization basis is incomplete: agent_id={agent_id}, controller={controller}"
            ))
        })
        .map(Some)
}

fn agent_direct_authorization_basis_from_record(
    record: &AgentPairingState,
) -> Option<
    arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis,
> {
    let provision_refs = record.provision_event_refs.as_ref()?;
    let refs = [
        provision_refs
            .get("provision_event_id")
            .and_then(Value::as_str),
        record.authorized_event_ref.as_deref(),
    ];
    let event_refs = refs
        .into_iter()
        .map(|event_ref| EventId::new(event_ref?.to_owned()).ok())
        .collect::<Option<Vec<_>>>()?;
    let basis =
        arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationBasis::agent_controller(event_refs);
    basis.validate_shape().ok()?;
    Some(basis)
}

#[salvo::oapi::endpoint(operation_id = "org.arkret.coland.account.register", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.account.register"))]
async fn local_account_register(
    depot: &mut Depot,
    body: JsonBody<LocalAccountRegisterRequestBody>,
) -> JsonResult<ColandAccountRegisterOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let did =
        validate_did(&body.did).map_err(|_| AppError::param_invalid("invalid account DID"))?;
    let principal_id = arkret_wire::project_did_to_core_id(&did)
        .map_err(|error| AppError::param_invalid(format!("invalid account DID: {error}")))?;

    let localpart = normalize_account_localpart_for_request(&body.handle)?;
    let account_exists = state
        .identities()
        .account(&arkret_wire::AccountId::new(
            principal_id.clone(),
            state.service_core_id().clone(),
        ))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .is_some();
    let localpart_exists = state
        .identities()
        .localpart_owner(&localpart)
        .await
        .map_err(localpart_persistence_error)?
        .is_some();
    if account_exists || localpart_exists {
        return Err(crate::app_error!(
            DuplicateConflict,
            "account already exists",
        ));
    }

    let account_id = arkret_wire::AccountId::new(
        principal_id.clone(),
        arkret_wire::DidCoreId::new(state.service_id().to_owned())
            .map_err(|error| AppError::internal(format!("service id is invalid: {error}")))?,
    );
    let created_at = now();
    let display_name = body
        .display_name
        .clone()
        .or_else(|| Some(body.handle.trim_start_matches('@').to_owned()));
    let identity = state
        .identities()
        .register_account(coland_services::identity::RegisterAccountCommand {
            account_id: account_id.clone(),
            localpart: localpart.clone(),
            display_name: display_name.clone(),
            created_at,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let account = AccountRecord {
        pk: identity.account_pk,
        account_id,
        principal_id: principal_id.clone(),
        localpart,
        display_name,
        biography: None,
        avatar_blob_ref: None,
        created_at,
    };
    if let Some(device_id) = body.device_id.as_deref() {
        let device_id = validate_device_id(device_id)
            .map_err(|_| AppError::param_invalid("invalid device_id"))?;
        put_account_device_placeholder(
            state,
            principal_id.as_str(),
            account.display_name.clone(),
            device_id.as_str(),
        )
        .await?;
    }
    append_audit_log(
        state,
        Some(principal_id.as_str()),
        "account.register",
        json!({"handle": account.handle(), "via": "local"}),
        "accepted",
    )
    .await;

    json_ok(account_response(account, state))
}

#[salvo::oapi::endpoint(operation_id = "org.arkret.coland.account.me", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.account.me"))]
async fn local_account_me(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<ColandAccountRegisterOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let account = state
        .identities()
        .account(&arkret_wire::AccountId::new(
            DidCoreId::new(session.actor.clone())
                .map_err(|error| AppError::internal(format!("invalid session actor: {error}")))?,
            state.service_core_id().clone(),
        ))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;

    json_ok(account_response(account, state))
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.accounts.localparts.list",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.accounts.localparts.list"))]
async fn list_account_localparts(
    account_principal_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountLocalpartListOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_account_localparts_bearer(state, req)?;
    let account_principal_id = account_core_id_from_path(account_principal_id.into_inner())?;
    let account_pk = local_account_pk(state, &account_principal_id).await?;
    let records = state
        .identities()
        .account_localparts(account_pk)
        .await
        .map_err(localpart_persistence_error)?;
    let primary_localpart = records
        .iter()
        .find(|record| record.is_primary)
        .map(|record| record.localpart.clone());
    json_ok(AccountLocalpartListOutcome {
        account_principal_id,
        primary_localpart,
        localparts: records.into_iter().map(account_localpart_view).collect(),
    })
}

#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.accounts.localparts.add",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.accounts.localparts.add"))]
async fn add_account_localpart(
    account_principal_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountLocalpartAddRequestBody>,
) -> JsonResult<AccountLocalpartMutationOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_account_localparts_bearer(state, req)?;
    let account_principal_id = account_core_id_from_path(account_principal_id.into_inner())?;
    let account_pk = local_account_pk(state, &account_principal_id).await?;
    let body = body.into_inner();
    let localpart = normalize_account_localpart_for_request(&body.localpart)?;
    let existing = state
        .identities()
        .account_localparts(account_pk)
        .await
        .map_err(localpart_persistence_error)?;
    let primary = body.is_primary.unwrap_or(existing.is_empty()) || existing.is_empty();
    let record = state
        .identities()
        .add_localpart(account_pk, &localpart, primary)
        .await
        .map_err(localpart_persistence_error)?;
    append_audit_log(
        state,
        Some(account_principal_id.as_str()),
        "account.localpart.add",
        json!({
            "account_principal_id": account_principal_id,
            "localpart": localpart,
            "is_primary": record.is_primary,
        }),
        "accepted",
    )
    .await;
    json_ok(AccountLocalpartMutationOutcome {
        localpart: account_localpart_view(record),
    })
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.read.viewer.v1"))]
pub(crate) async fn account_viewer(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<AccountView> {
    let session = {
        let state = depot.get_typed::<AppState>().expect("state injected");
        aa.authenticated_session(state, req).await?
    };
    account_viewer_impl(session, depot).await
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "org.arkret.coland.admin.account.query.viewer"))]
pub(crate) async fn admin_account_viewer(
    admin: crate::routing::admin::AdminAuth,
    depot: &mut Depot,
) -> JsonResult<AccountView> {
    let session = admin.session()?;
    account_viewer_impl(session, depot).await
}

/// `session` is the caller already authenticated by the wrapping handler
/// (the self bearer path or the `RequireAdmin` gate).
async fn account_viewer_impl(
    session: coland_services::identity::SessionIdentityState,
    depot: &mut Depot,
) -> JsonResult<AccountView> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let account = state
        .identities()
        .account(&arkret_wire::AccountId::new(
            DidCoreId::new(session.actor.clone())
                .map_err(|error| AppError::internal(format!("invalid session actor: {error}")))?,
            state.service_core_id().clone(),
        ))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("not found"))?;
    let devices = account_device_summaries(state, &session.actor).await?;
    let primary_handle_claim = account_primary_handle_claim(state, &account)
        .await
        .and_then(|value| serde_json::from_value(value).ok());
    let profile = accepted_account_profile(state, &session.actor).await?;
    let is_server_admin = state.is_admin_principal(&session.actor);
    json_ok(AccountView {
        principal_id: account.principal_id.clone(),
        state: state.account_lifecycle_status(account.principal_id.as_str()),
        devices,
        primary_handle_claim,
        primary_handle_claim_ref: None,
        handle_claim_digests: Vec::new(),
        profile,
        is_server_admin,
    })
}

/// `POST /_coland/gate/account/project` — deployment-local Station
/// projection invoked only after the Account Authority has completed the
/// canonical registration operation.
///
/// This Station endpoint is the deployment projection edge used by
/// the Account Authority after it has verified the published-DID registration
/// branch.
/// It requires the configured service bearer, never accepts the client-facing
/// `identity_creation` branch, and does not create a handle as a side effect.
#[salvo::oapi::endpoint(
    operation_id = "org.arkret.coland.gate.account.command.project",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "org.arkret.coland.gate.account.command.project")
)]
async fn project_account(
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountProjectionRequestBody>,
) -> JsonResult<AccountProjectionRegisterOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    require_embedded_webvh_registration_bearer(state, req)?;
    let body = body.into_inner();
    body.validate().map_err(AppError::param_invalid)?;
    let principal_id = body.principal_id.clone();
    let registration_audit = enforce_account_registration_policy(
        state,
        principal_id.as_str(),
        body.did.as_str(),
        None,
        None,
    )
    .await?;
    let existing = state
        .identities()
        .account(&arkret_wire::AccountId::new(
            principal_id.clone(),
            state.service_core_id().clone(),
        ))
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    if let Some(existing_account) = existing {
        if let Some(device_id) = body.device_id.as_ref() {
            put_account_device_placeholder(
                state,
                principal_id.as_str(),
                existing_account
                    .display_name
                    .clone()
                    .or_else(|| body.display_name.clone()),
                device_id.as_str(),
            )
            .await?;
        }
        let audit_handle =
            (!existing_account.localpart.is_empty()).then(|| existing_account.handle());
        append_account_registration_audit(
            state,
            principal_id.as_str(),
            audit_handle.as_deref(),
            &registration_audit,
        )
        .await;
        let devices = account_device_summaries(state, principal_id.as_str()).await?;
        let primary_handle_claim = account_primary_handle_claim(state, &existing_account)
            .await
            .and_then(|value| serde_json::from_value(value).ok());
        return json_ok(AccountProjectionRegisterOutcome {
            principal_id: body.principal_id,
            state: AccountStatus::Active,
            devices,
            primary_handle_claim,
            profile: None,
            registration_audit,
        });
    }
    let account_id = arkret_wire::AccountId::new(
        principal_id.clone(),
        arkret_wire::DidCoreId::new(state.service_id().to_owned())
            .map_err(|error| AppError::internal(format!("service id is invalid: {error}")))?,
    );
    let created_at = now();
    let identity = state
        .identities()
        .register_account(coland_services::identity::RegisterAccountCommand {
            account_id: account_id.clone(),
            localpart: String::new(),
            display_name: body.display_name.clone(),
            created_at,
        })
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let account = AccountRecord {
        pk: identity.account_pk,
        account_id,
        principal_id,
        localpart: String::new(),
        display_name: body.display_name.clone(),
        biography: None,
        avatar_blob_ref: None,
        created_at,
    };
    if let Some(device_id) = body.device_id.as_ref() {
        // A device becomes `verified` only through an accepted and projected
        // `ak.device.authorize` carrying its possession proof. Minting a
        // `verified`-without-key row here would carry no
        // `device_public_key`, so no projected-device-set verifier could
        // resolve a signing key for it.
        // Create an `unverified`, key-less placeholder so the session / device
        // list works until the real enrollment event lands (mirrors the
        // OAuth-introspection lazy-create path in `auth::ensure_oauth_device`).
        // PCR genesis can precede account projection, so this must be
        // insert-if-absent: an already verified founding device is canonical
        // Event state and must never be downgraded by account creation.
        put_account_device_placeholder(
            state,
            account.principal_id.as_str(),
            account.display_name.clone(),
            device_id.as_str(),
        )
        .await?;
    }
    let audit_handle = (!account.localpart.is_empty()).then(|| account.handle());
    append_account_registration_audit(
        state,
        account.principal_id.as_str(),
        audit_handle.as_deref(),
        &registration_audit,
    )
    .await;
    let devices = account_device_summaries(state, account.principal_id.as_str()).await?;
    let primary_handle_claim = account_primary_handle_claim(state, &account)
        .await
        .and_then(|value| serde_json::from_value(value).ok());
    json_ok(AccountProjectionRegisterOutcome {
        principal_id: body.principal_id,
        state: AccountStatus::Active,
        devices,
        primary_handle_claim,
        profile: None,
        registration_audit,
    })
}

#[salvo::handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.command.update_profile.v1"))]
async fn update_profile(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<AccountUpdateProfileRequestBody>,
) -> JsonResult<AccountUpdateProfileResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    validate_profile_request(&body)?;
    let session_actor =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    let event = &body.profile_event.event;
    if event.actor_id != session_actor {
        return Err(crate::app_error!(
            FailedPrecondition,
            "profile Event actor is not the authenticated account",
        ));
    }
    let committed_at = chrono::Utc::now();
    let method = arkret_wire::DidUrl::new(
        crate::routing::federation::federation_service_signature_key_id(
            state.service_did().as_str(),
        ),
    )
    .map_err(|error| AppError::internal(error.to_string()))?;
    // Signer device, PCR lineage, create/update presence, target, patch,
    // expected_state_digest and accountability are decided by the PCR unit
    // at the locked cut.
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
        .map_err(|error| profile_admission_error(error.conflict_code(), error.detail()))?;
    let outcome = state
        .persistence()
        .admit_actor_profile(coland_storage::ActorProfileAdmissionWrite {
            commit: transaction,
            queued_at: committed_at,
        })
        .await
        .map_err(|error| profile_admission_error(error.conflict_code(), &error.to_string()))?;
    let record = match outcome {
        coland_storage::ActorProfileAdmissionOutcome::Committed(record)
        | coland_storage::ActorProfileAdmissionOutcome::Duplicate(record) => record,
    };
    json_ok(AccountUpdateProfileResponseBody {
        profile: AccountMaterializedProfile::new(record.profile)
            .map_err(|error| AppError::internal(error.to_string()))?,
        commit: record.commit,
    })
}

/// `account_profile_event_submission`: a patch path outside the self-service
/// surface is `unsupported_profile_patch_path`; every other shape failure is
/// a schema violation.
fn validate_profile_request(body: &AccountUpdateProfileRequestBody) -> Result<(), AppError> {
    let event = &body.profile_event.event;
    if event.kind == arkret_wire::EventKind::ProfileUpdate
        && let Ok(update) = serde_json::from_value::<
            arkret_models_collaboration::events_payloads::ActorProfileUpdatePayload,
        >(Value::Object(event.payload.clone().into_iter().collect()))
        && let Err(error) = update.validate_for_account_self_service()
    {
        return Err(crate::app_error!(
            UnsupportedProfilePatchPath,
            error.to_string(),
        ));
    }
    body.validate()
        .map_err(|error| AppError::schema_violation(format!("profile_event: {error}")))
}

/// The registered `ak.self.account.command.update_profile.v1` mapping:
/// deterministic admission guards are `failed_precondition` (with the
/// `accountability_grant_missing` reason), a head that moved before commit is
/// retry-safe `revision_unavailable`, and signer-device refusals keep their
/// device codes (device-lifecycle §8.2.2).
pub(crate) fn profile_admission_error(
    code: Option<coland_storage::ConflictCode>,
    detail: &str,
) -> AppError {
    use coland_storage::ConflictCode;
    match code {
        Some(ConflictCode::AccountabilityGrantMissing) => {
            crate::app_error!(FailedPrecondition, detail)
                .with_reason_code(arkret_wire::ReasonCode::ACCOUNTABILITY_GRANT_MISSING)
        }
        Some(ConflictCode::FailedPrecondition) => {
            crate::app_error!(FailedPrecondition, detail)
        }
        Some(ConflictCode::TemporarilyUnavailable | ConflictCode::CasConflict) => {
            crate::app_error!(RevisionUnavailable, detail)
        }
        Some(ConflictCode::DuplicateConflict | ConflictCode::EventHashCollision) => {
            crate::app_error!(DuplicateConflict, detail)
        }
        Some(ConflictCode::SignatureInvalid) => {
            crate::app_error!(SignatureInvalid, detail)
        }
        Some(ConflictCode::SchemaViolation | ConflictCode::EventIdDigestMismatch) => {
            AppError::schema_violation(detail)
        }
        Some(ConflictCode::DeviceRevoked) => {
            crate::app_error!(DeviceRevoked, detail)
        }
        Some(ConflictCode::DeviceRevocationPending) => {
            crate::app_error!(DeviceRevocationPending, detail)
        }
        Some(ConflictCode::DeviceGenerationFenced) => {
            crate::app_error!(DeviceGenerationFenced, detail)
        }
        Some(ConflictCode::DeviceUnauthorized) => {
            crate::app_error!(DeviceUnauthorized, detail)
        }
        _ => AppError::internal(detail),
    }
}

/// The authenticated local account's accepted global Actor Profile, read from
/// the `actor_profile` typed current of its PCR.
pub(crate) async fn accepted_account_profile(
    state: &AppState,
    principal: &str,
) -> Result<Option<AccountMaterializedProfile>, AppError> {
    let account = arkret_wire::AccountId::new(
        DidCoreId::new(principal.to_owned())
            .map_err(|error| AppError::internal(format!("invalid account principal: {error}")))?,
        state.service_core_id().clone(),
    );
    state
        .persistence()
        .current_actor_profile(&account)
        .await
        .map_err(|error| AppError::internal(format!("read accepted Actor Profile: {error}")))?
        .map(|record| {
            AccountMaterializedProfile::new(record.profile)
                .map_err(|error| AppError::internal(error.to_string()))
        })
        .transpose()
}

/// One resolved row: the current value, the exact Event that produced it and
/// its covering PCR Commit. A remote account's PCR is not hosted here, so it
/// is simply unavailable.
async fn resolved_actor_profile_evidence(
    state: &AppState,
    actor_id: &arkret_wire::ActorId,
) -> Result<Option<ResolvedActorProfile>, AppError> {
    let Some(account) = actor_id.as_account_id() else {
        return Ok(None);
    };
    if account.station_id != state.service_core_id() {
        return Ok(None);
    }
    let Some(record) = state
        .persistence()
        .current_actor_profile(account)
        .await
        .map_err(|error| AppError::internal(format!("read accepted Actor Profile: {error}")))?
    else {
        return Ok(None);
    };
    let row = ResolvedActorProfile {
        actor_id: actor_id.clone(),
        actor_profile: record.profile,
        profile_event: record.event,
        profile_commit: record.commit,
        account_status: None,
    };
    arkret_models_collaboration::actor_profile_resolution::validate_resolved_actor_profile(&row)
        .map_err(|error| {
            AppError::internal(format!(
                "stored Actor Profile evidence is inconsistent: {error}"
            ))
        })?;
    Ok(Some(row))
}
#[salvo::oapi::endpoint(operation_id = "ak.self.actor_profile.read.resolve", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.actor_profile.read.resolve.v1"))]
async fn resolve_actor_profiles(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ActorProfileResolveRequestBody>,
) -> JsonResult<ActorProfileResolveResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;

    // Authorization is evaluated before any target profile read. A PCR is
    // never a legal relationship selector even if its owner happens to be a
    // member there through device projections.
    let selector_is_pcr = state
        .persistence()
        .principal_resolution_for_realm(&body.realm_id)
        .await
        .map_err(|error| AppError::internal(format!("classify Actor Profile selector: {error}")))?
        .is_some();
    let caller_joined = !selector_is_pcr
        && crate::routing::realm_has_member(
            state,
            body.realm_id.as_str(),
            &crate::routing::identity::session_actor::session_actor_from_credential(
                state, &session,
            )?
            .to_string(),
        )
        .await;
    if !caller_joined {
        // The caller's own membership is the authorization basis, so its
        // absence is not a per-actor outcome: the request has no basis at all
        // and gets one `not_found` that says nothing about any requested actor.
        // A Principal Control Realm selector lands here too, indistinguishable
        // from a Realm the caller simply is not in.
        return Err(AppError::not_found("actor profiles unavailable"));
    }

    let mut profiles = Vec::new();
    let mut failures = Vec::new();
    for actor_id in &body.actor_ids {
        let target_joined =
            crate::routing::realm_has_member(state, body.realm_id.as_str(), &actor_id.to_string())
                .await;
        let resolved = if target_joined {
            resolved_actor_profile_evidence(state, actor_id).await?
        } else {
            None
        };
        match resolved {
            Some(profile) => profiles.push(profile),
            None => failures.push(ActorProfileResolveFailure {
                actor_id: actor_id.clone(),
                reason: ActorProfileResolveFailureReason::ProfileUnavailable,
            }),
        }
    }
    let outcome = ActorProfileResolveResponseBody {
        profiles,
        failures: (!failures.is_empty()).then_some(failures),
    };
    outcome
        .validate_covers(&body.actor_ids)
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.identity.read.resolution_audit",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.identity.read.resolution_audit.v1"))]
async fn read_principal_resolution_audit(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    res: &mut Response,
    body: JsonBody<PrincipalResolutionAuditRequestBody>,
) -> JsonResult<PrincipalResolutionAuditEvidence> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    if body.account_id.principal_id.as_str() != session.actor
        || body.account_id.station_id.as_str() != state.service_id()
    {
        return Err(AppError::not_found(
            "principal resolution audit unavailable",
        ));
    }
    let record = state
        .persistence()
        .principal_resolution_by_account_id(&body.account_id)
        .await
        .map_err(|error| AppError::internal(format!("load principal resolution audit: {error}")))?
        .ok_or_else(|| AppError::not_found("principal resolution audit unavailable"))?;

    let full_history = state
        .persistence()
        .principal_resolution_history(&body.account_id, None, 258)
        .await
        .map_err(|error| {
            AppError::internal(format!("load principal resolution history: {error}"))
        })?;
    if full_history.first().map(|e| &e.event_id) != Some(&record.current_event.event_id) {
        return Err(crate::app_error!(
            TemporarilyUnavailable,
            "resolution audit current changed during read"
        ));
    }
    let cursor_position = if let Some(cursor) = body.after_resolution_event_ref.as_ref() {
        if cursor == &record.current_event.event_id {
            return Err(
                AppError::param_invalid("resolution history ancestor is unknown")
                    .with_reason_code("resolution_history_ancestor_unknown"),
            );
        }
        state
            .persistence()
            .principal_resolution_history(&body.account_id, Some(cursor.as_str()), 1)
            .await
            .map_err(|_| {
                AppError::param_invalid("resolution history ancestor is unknown")
                    .with_reason_code("resolution_history_ancestor_unknown")
            })?;
        full_history
            .iter()
            .position(|event| event.event_id == *cursor)
    } else {
        None
    };
    let available_predecessors = full_history
        .iter()
        .skip(1)
        .take_while(|event| event.event_id != record.genesis_event.event_id)
        .take(
            cursor_position
                .map(|position| position.saturating_sub(1))
                .unwrap_or(usize::MAX),
        )
        .cloned()
        .collect::<Vec<_>>();
    let requested_depth = usize::from(body.history_depth.unwrap_or(0));
    let mut predecessor_resolution_events = available_predecessors
        .iter()
        .take(requested_depth)
        .cloned()
        .collect::<Vec<_>>();
    // `history_depth = 0` means "return only the current Event", not "claim
    // there is no omitted history". Completeness is true only when the
    // bounded segment reaches genesis (which is carried separately) or the
    // caller's exclusive ancestor cursor.
    let history_complete = predecessor_resolution_events.len() == available_predecessors.len();
    let next_audit_cursor = if !history_complete {
        let oldest = predecessor_resolution_events
            .last()
            .unwrap_or(&record.current_event);
        let next = &available_predecessors[predecessor_resolution_events.len()];
        let payload: arkret_models_identity::PrincipalResolutionUpdatePayload =
            serde_json::from_value(
                serde_json::to_value(&oldest.payload)
                    .map_err(|e| AppError::internal(e.to_string()))?,
            )
            .map_err(|e| AppError::internal(e.to_string()))?;
        let accepted = state
            .persistence()
            .committed_event(&next.event_id)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?
            .ok_or_else(|| AppError::internal("audit predecessor Commit missing"))?;
        if accepted.commit.commit_id != payload.expected_revision.commit_id
            || accepted.commit.stream_position != payload.expected_revision.stream_position
            || accepted.commit.realm_id != record.pcr_realm_id
            || next.actor_id.as_account_id() != Some(&record.account_id)
        {
            return Err(AppError::internal(
                "audit cursor does not bind the signed source revision",
            ));
        }
        Some(next.event_id.clone())
    } else {
        None
    };
    predecessor_resolution_events.reverse();
    let (mut method_history_evidence, _) =
        crate::routing::system::principal_resolution::principal_method_history_evidence(
            state,
            &record.projection,
            false,
        )
        .await?;
    let initial: arkret_models_identity::ResolutionCommitment = serde_json::from_value(
        record
            .genesis_event
            .payload
            .get("object")
            .and_then(|o| o.get("initial_resolution"))
            .cloned()
            .ok_or_else(|| AppError::internal("audit genesis initial resolution missing"))?,
    )
    .map_err(|e| AppError::internal(e.to_string()))?;
    match &mut method_history_evidence {
        arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog { boundary, .. }
        | arkret_models_identity::ResolutionMethodHistoryEvidence::DidWebDocument {
            boundary,
            ..
        }
        | arkret_models_identity::ResolutionMethodHistoryEvidence::DidKeyExpansion {
            boundary,
            ..
        } => {
            boundary.from_method_history_head = initial.method_history_head;
            boundary.from_version_id = initial.version_id;
        }
    }

    let principal_genesis_commit = state
        .persistence()
        .committed_event(&record.genesis_event.event_id)
        .await
        .map_err(|error| AppError::internal(format!("load PCR genesis commit: {error}")))?
        .map(|committed| committed.commit)
        .ok_or_else(|| AppError::not_found("principal resolution audit unavailable"))?;
    let current_resolution_commit = state
        .persistence()
        .committed_event(&record.current_event.event_id)
        .await
        .map_err(|error| AppError::internal(format!("load current resolution commit: {error}")))?
        .map(|committed| committed.commit)
        .ok_or_else(|| AppError::not_found("principal resolution audit unavailable"))?;
    let mut predecessor_resolution_commits =
        Vec::with_capacity(predecessor_resolution_events.len());
    for event in &predecessor_resolution_events {
        let commit = state
            .persistence()
            .committed_event(&event.event_id)
            .await
            .map_err(|error| AppError::internal(format!("load resolution commit: {error}")))?
            .map(|committed| committed.commit)
            .ok_or_else(|| AppError::not_found("principal resolution audit unavailable"))?;
        predecessor_resolution_commits.push(commit);
    }

    res.headers_mut().insert(
        salvo::http::header::CACHE_CONTROL,
        salvo::http::HeaderValue::from_static("no-store, no-transform"),
    );
    let evidence = PrincipalResolutionAuditEvidence {
        account_id: record.account_id,
        principal_control_realm_id: record.pcr_realm_id,
        principal_genesis_commit,
        principal_genesis_event: record.genesis_event,
        current_resolution_event: record.current_event,
        predecessor_resolution_events,
        predecessor_resolution_commits,
        history_complete,
        current_resolution_commit,
        next_audit_cursor,
        method_history_evidence: Some(method_history_evidence),
    };
    evidence
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(evidence)
}

fn direct_current_membership_blocker(
    facts: Option<&coland_storage::DirectConversationDurableState>,
    actor: &ActorId,
    peer: &ActorId,
) -> Option<DirectConversationSendBlocker> {
    let facts = facts?;
    let Some(binding) = facts.binding.as_ref().map(|binding| &binding.binding) else {
        return Some(DirectConversationSendBlocker::MemberCountInvalid);
    };
    let participants = binding
        .unordered_participant_ids
        .iter()
        .collect::<BTreeSet<_>>();
    let members = facts
        .members
        .iter()
        .map(|member| &member.member_id)
        .collect::<BTreeSet<_>>();
    if binding.unordered_participant_ids.len() != 2
        || participants.len() != 2
        || members != participants
    {
        return Some(DirectConversationSendBlocker::MemberCountInvalid);
    }
    let joined = |participant: &ActorId| {
        facts
            .members
            .iter()
            .any(|member| &member.member_id == participant && member.membership == "join")
    };
    if !joined(actor) || !joined(peer) {
        return Some(DirectConversationSendBlocker::PeerNotJoinedMls);
    }
    None
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.direct_conversation.read.resolve",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.direct_conversation.read.resolve.v1"))]
async fn direct_conversation_resolve(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<DirectConversationResolveRequestBody>,
) -> JsonResult<DirectConversationResolveResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let body = body.into_inner();
    let peer_descriptor = &body.peer;
    let actor = super::session_actor::validated_session_actor(state, &session).await?;
    if peer_descriptor.contact_actor_id() == actor {
        return Err(AppError::param_invalid("invalid direct conversation peer"));
    }
    let peer = peer_descriptor.contact_actor_id();
    if let ContactPeer::Agent {
        controller_account_id,
        ..
    } = peer_descriptor
    {
        let record = state
            .agent_pairings()
            .agent(peer.signing_principal_id().as_str())
            .await
            .map_err(|error| AppError::internal(format!("Agent lookup failed: {error}")))?;
        if record
            .as_ref()
            .map(|record| record.controller_principal_id.as_str())
            != Some(controller_account_id.principal_id.as_str())
        {
            return Err(direct_resolve_precondition(
                arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
                "direct conversation Agent controller binding is unavailable",
            ));
        }
    }

    // The peer MAY be either an active controller-owned local Agent or a
    // canonical Contact. Keep a tombstoned Contact visible here: once durable
    // coordinates exist, a scope/lifecycle change suspends sending but must
    // not make those coordinates disappear.
    let scope = "direct_message";
    let agent_basis = agent_direct_authorization_basis(
        state,
        &session.actor,
        peer.signing_principal_id().as_str(),
    )
    .await?;
    let contact = if agent_basis.is_some() {
        None
    } else {
        let contact = direct_contact_for_pair(state, &actor, &peer).await?;
        if contact.is_none() {
            return Err(direct_resolve_precondition(
                arkret_wire::ErrorCode::DIRECT_CONVERSATION_UNAVAILABLE,
                "direct conversation is unavailable",
            )
            .with_private_detail(format!(
                "no owned active Agent authorization or accepted contact projection: requester_id={}, peer={peer}",
                session.actor
            )));
        }
        contact
    };
    let accepted_contact = if agent_basis.is_some() {
        None
    } else {
        accepted_contact_for_pair(state, &actor, &peer, scope).await?
    };

    let pair_key = direct_pair_key(state, &actor, &peer)?;
    let pair_key_hash = Hash::new(pair_key.clone())
        .map_err(|error| AppError::internal(format!("direct pair key invalid: {error}")))?;

    // Existing coordinates and their state come from the accepted durable
    // founding/current-state cut.  In particular, a live binding no longer
    // depends on process hydration having replayed it into ContactService.
    let mut durable = state
        .event_queries()
        .direct_conversation_durable_state(state.config().trust_domain.as_str(), &pair_key)
        .await
        .map_err(|error| {
            AppError::internal(format!("direct durable-state lookup failed: {error}"))
        })?;
    if let Some(facts) = &durable
        && facts.peer_mls_admission
            == arkret_models_collaboration::direct_conversation::DirectConversationPeerMlsAdmission::Pending
    {
        let realm_id = RealmId::new(facts.founding_slot.realm_id.clone())
            .map_err(|error| AppError::internal(format!("Direct Realm id: {error}")))?;
        crate::state::refresh_direct_conversation_peer_claim(state, &realm_id)
            .await
            .map_err(|error| AppError::internal(format!("Direct peer claim refresh: {error}")))?;
        durable = state
            .event_queries()
            .direct_conversation_durable_state(state.config().trust_domain.as_str(), &pair_key)
            .await
            .map_err(|error| AppError::internal(format!("Direct refreshed state: {error}")))?;
    }
    let raw_binding = durable
        .as_ref()
        .and_then(|facts| facts.binding.as_ref())
        .map(durable_binding_record)
        .transpose()?;
    if let Some(binding) = raw_binding {
        let coordinates = direct_coordinates(pair_key_hash, &binding)?;
        let group_state = durable
            .as_ref()
            .and_then(|facts| facts.group_state_ref.clone());
        let mut group_state_ref = group_state.clone();
        let projection = state.projections().snapshot();
        if projection.realm_is_destroyed(&binding.realm_id)
            || projection.realm_is_tombstoned(&binding.realm_id)
        {
            return json_ok(DirectConversationResolveResponseBody::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::RealmTerminalFault],
                group_state_ref,
            });
        }
        if contact
            .as_ref()
            .is_some_and(|contact| contact.status != "accepted")
        {
            return json_ok(DirectConversationResolveResponseBody::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::ContactScopeStale],
                group_state_ref,
            });
        }
        if let Some(blocker) = direct_current_membership_blocker(durable.as_ref(), &actor, &peer) {
            return json_ok(DirectConversationResolveResponseBody::Suspended {
                coordinates,
                blockers: vec![blocker],
                group_state_ref,
            });
        }
        if state.account_lifecycle_state(&session.actor) != "active"
            || (agent_basis.is_none()
                && state.account_lifecycle_state(peer.signing_principal_id().as_str()) != "active")
        {
            return json_ok(DirectConversationResolveResponseBody::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::PolicyStale],
                group_state_ref,
            });
        }
        if let Some(facts) = &durable
            && facts.binding.is_some()
        {
            let realm = RealmId::new(facts.founding_slot.realm_id.clone())
                .map_err(|error| AppError::internal(error.to_string()))?;
            let authority = state
                .authority_commits()
                .current_authority(&realm)
                .await
                .map_err(|error| AppError::internal(error.to_string()))?;
            if authority.is_some_and(|authority| authority.service_id != state.service_core_id())
                && facts.group_current_exact_pair.is_none()
            {
                if !crate::state::foreign_direct_mls::refresh(state, &realm, &actor)
                    .await
                    .unwrap_or(false)
                {
                    return json_ok(
                        DirectConversationResolveResponseBody::TemporarilyUnavailable {
                            retry_after_ms: Some(250),
                        },
                    );
                }
                durable = state
                    .event_queries()
                    .direct_conversation_durable_state(
                        state.config().trust_domain.as_str(),
                        &pair_key,
                    )
                    .await
                    .map_err(|error| AppError::internal(error.to_string()))?;
                if durable
                    .as_ref()
                    .is_none_or(|facts| facts.group_current_exact_pair.is_none())
                {
                    return json_ok(
                        DirectConversationResolveResponseBody::TemporarilyUnavailable {
                            retry_after_ms: Some(250),
                        },
                    );
                }
            }
        }
        group_state_ref = durable
            .as_ref()
            .and_then(|facts| facts.group_state_ref.clone());
        // The refresh may advance membership or lifecycle while material is
        // in flight. Evaluate deterministic blockers again at the published cut.
        if let Some(blocker) = direct_current_membership_blocker(durable.as_ref(), &actor, &peer) {
            return json_ok(DirectConversationResolveResponseBody::Suspended {
                coordinates,
                blockers: vec![blocker],
                group_state_ref,
            });
        }
        let projection = state.projections().snapshot();
        if projection.realm_is_destroyed(&binding.realm_id)
            || projection.realm_is_tombstoned(&binding.realm_id)
        {
            return json_ok(DirectConversationResolveResponseBody::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::RealmTerminalFault],
                group_state_ref,
            });
        }
        if state.account_lifecycle_state(&session.actor) != "active"
            || (agent_basis.is_none()
                && state.account_lifecycle_state(peer.signing_principal_id().as_str()) != "active")
        {
            return json_ok(DirectConversationResolveResponseBody::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::PolicyStale],
                group_state_ref,
            });
        }
        if durable
            .as_ref()
            .and_then(|facts| facts.group_current_exact_pair)
            != Some(true)
        {
            return json_ok(DirectConversationResolveResponseBody::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::MlsReconcileRequired],
                group_state_ref,
            });
        }
        let mut send_blockers = Vec::new();
        if projection.realm_ordinary_writes_blocked(&binding.realm_id) {
            send_blockers.push(DirectConversationSendBlocker::PolicyStale);
        }
        if let Some(contact) = contact.as_ref() {
            let current_contact_evidence=contact.status=="accepted" && contact.current_state.initial_identity.is_some() && contact.current_state.round_basis.as_ref().is_some_and(|r|Some(&r.contact_round_id)==contact.contact_round_id.as_ref()) && contact.current_state.directions.len()==2 && contact.current_state.directions.iter().all(|d|d.scope_instances.iter().any(|i|i.contact_scope==arkret_models_collaboration::contact_operations::ContactScope::DirectMessage) && d.closed_round.as_ref().is_none_or(|c|Some(&c.contact_round_id)!=contact.contact_round_id.as_ref()));
            let known_closed = if let (Some(round), Some(direction)) = (
                contact.contact_round_id.as_ref(),
                contact.current_state.directions.first(),
            ) {
                state
                    .contacts()
                    .known_round_closure(
                        &state.config().trust_domain,
                        direction.head_operation.holder(),
                        direction.head_operation.peer(),
                        round,
                    )
                    .await
                    .map_err(|e| AppError::internal(e.to_string()))?
                    .is_some()
            } else {
                true
            };
            let current_contact_evidence = current_contact_evidence && !known_closed;
            if !current_contact_evidence {
                send_blockers.push(DirectConversationSendBlocker::ContactScopeStale);
            }
        }
        if agent_basis.is_some() {
            let agent_active = state
                .agent_pairings()
                .agent(peer.signing_principal_id().as_str())
                .await
                .map_err(|error| AppError::internal(format!("Agent lookup failed: {error}")))?
                .is_some_and(|agent| agent.state == AgentLifecycleState::Active);
            if !agent_active {
                send_blockers.push(DirectConversationSendBlocker::AgentRuntimeUnavailable);
            }
        }
        send_blockers.sort_by_key(|blocker| format!("{blocker:?}"));
        send_blockers.dedup();
        let Some(group_state_ref) = group_state_ref else {
            return json_ok(DirectConversationResolveResponseBody::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::MlsReconcileRequired],
                group_state_ref: None,
            });
        };
        return json_ok(DirectConversationResolveResponseBody::Found {
            coordinates,
            group_state_ref,
            send_blockers,
        });
    }

    if let Some(facts) = durable.as_ref() {
        let coordinates = direct_slot_coordinates(pair_key_hash.clone(), &facts.founding_slot)?;
        if contact
            .as_ref()
            .is_some_and(|contact| contact.status != "accepted")
        {
            return json_ok(DirectConversationResolveResponseBody::Suspended {
                coordinates,
                blockers: vec![DirectConversationSendBlocker::ContactScopeStale],
                group_state_ref: facts.group_state_ref.clone(),
            });
        }
        return json_ok(DirectConversationResolveResponseBody::Provisional {
            coordinates,
            authorization_basis: facts.founding_slot.authorization_basis.clone(),
            group_state_ref: facts.group_state_ref.clone(),
            initial_exact_pair_group_state_ref: facts.initial_exact_pair_group_state_ref.clone(),
            peer_mls_admission: facts.peer_mls_admission,
        });
    }

    // No accepted binding yet. Creation is founder-only: this endpoint never creates, and waiting
    // never grants create authority to the non-founder — there is no timeout fallback or takeover.
    let founder = direct_founder_for_pair(
        state,
        &actor,
        &peer,
        contact.as_ref(),
        agent_basis.is_some(),
    )
    .await?;
    if agent_basis.is_none() && accepted_contact.is_none() {
        tracing::warn!(
            diagnostic = "accepted_contact",
            "Direct founding resolution is unavailable"
        );
        return json_ok(
            DirectConversationResolveResponseBody::TemporarilyUnavailable {
                retry_after_ms: None,
            },
        );
    }
    match founder {
        Some(founder) if founder == actor.to_string() => {
            if let Some(basis) = agent_basis.as_ref() {
                for event_ref in &basis.event_refs {
                    let Some(accepted) = state
                        .event_queries()
                        .accepted_event(event_ref.as_str())
                        .await
                        .map_err(|error| {
                            AppError::internal(format!("Agent provision lookup failed: {error}"))
                        })?
                    else {
                        continue;
                    };
                    if accepted.kind != arkret_wire::EventKind::AgentProvision.as_str() {
                        continue;
                    }
                    let payload: arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload =
                        serde_json::from_value(accepted.envelope.get("payload").cloned().unwrap_or(Value::Null))
                            .map_err(|error| AppError::internal(format!("accepted Agent provision payload is invalid: {error}")))?;
                    if payload.agent_id != *peer.signing_principal_id()
                        || payload.controller_principal_id != *actor.signing_principal_id()
                        || accepted.actor_id != actor.to_string()
                        || accepted.canonical_digest != event_ref.event_digest().as_str()
                    {
                        return Err(AppError::internal(
                            "accepted Agent provision binding does not match the pair",
                        ));
                    }
                    let evidence =
                        DirectConversationFoundingAuthorityEvidence::from_agent_provision(
                            event_ref.clone(),
                            &payload,
                        )
                        .map_err(|error| {
                            AppError::internal(format!(
                                "Agent founding evidence is invalid: {error}"
                            ))
                        })?;
                    return json_ok(DirectConversationResolveResponseBody::CreationRequired {
                        next_founding_input: DirectConversationFoundingInput {
                            founding_authority_evidence: evidence,
                        },
                    });
                }
                return json_ok(
                    DirectConversationResolveResponseBody::TemporarilyUnavailable {
                        retry_after_ms: None,
                    },
                );
            }
            let Some(contact) = contact.as_ref() else {
                return json_ok(
                    DirectConversationResolveResponseBody::TemporarilyUnavailable {
                        retry_after_ms: None,
                    },
                );
            };
            let Some(contact_round_evidence) =
                social::direct::fresh_direct_contact_evidence(state, contact).await?
            else {
                tracing::warn!(
                    diagnostic = "fresh_contact_evidence",
                    "Direct founding resolution is unavailable"
                );
                return json_ok(
                    DirectConversationResolveResponseBody::TemporarilyUnavailable {
                        retry_after_ms: None,
                    },
                );
            };
            json_ok(DirectConversationResolveResponseBody::CreationRequired {
                next_founding_input: DirectConversationFoundingInput {
                    founding_authority_evidence:
                        DirectConversationFoundingAuthorityEvidence::Human {
                            contact_round_evidence,
                        },
                },
            })
        }
        Some(_) => json_ok(DirectConversationResolveResponseBody::AwaitingFounder {
            retry_after_ms: None,
        }),
        // The basis is not verifiable right now, so we cannot safely classify the pair.
        None => {
            tracing::warn!(
                diagnostic = "founder",
                "Direct founding resolution is unavailable"
            );
            json_ok(
                DirectConversationResolveResponseBody::TemporarilyUnavailable {
                    retry_after_ms: None,
                },
            )
        }
    }
}

async fn direct_contact_for_pair(
    state: &AppState,
    actor: &arkret_wire::ActorId,
    peer: &arkret_wire::ActorId,
) -> Result<Option<ContactRecord>, AppError> {
    let mut records = Vec::new();
    for (requester_id, target) in [(actor, peer), (peer, actor)] {
        if let Some(contact) = state
            .contacts()
            .contact_any(requester_id, target)
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
        {
            records.push(contact);
        }
    }
    Ok(records.into_iter().max_by(|left, right| {
        left.updated_at
            .cmp(&right.updated_at)
            .then_with(|| (left.status != "accepted").cmp(&(right.status != "accepted")))
    }))
}

fn direct_coordinates(
    pair_key: Hash,
    binding: &DirectConversationBindingRecord,
) -> Result<DirectConversationCoordinates, AppError> {
    Ok(DirectConversationCoordinates {
        pair_key,
        realm_id: RealmId::new(binding.realm_id.clone())
            .map_err(|error| AppError::internal(format!("stored direct Realm id: {error}")))?,
        main_strand_id: StrandId::new(binding.main_strand_id.clone())
            .map_err(|error| AppError::internal(format!("stored direct Strand id: {error}")))?,
        binding_event_ref: Some(
            EventId::new(binding.binding_event_ref.clone()).map_err(|error| {
                AppError::internal(format!("stored direct binding ref: {error}"))
            })?,
        ),
    })
}

pub(crate) fn durable_binding_record(
    current: &arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingCurrentValue,
) -> Result<DirectConversationBindingRecord, AppError> {
    current
        .binding
        .validate_shape()
        .map_err(|error| AppError::internal(error.to_string()))?;
    let binding = &current.binding;
    Ok(DirectConversationBindingRecord {
        participants_unordered: binding
            .unordered_participant_ids
            .iter()
            .map(ToString::to_string)
            .collect(),
        realm_id: binding.realm_id.to_string(),
        main_strand_id: binding.main_strand_id.to_string(),
        created_at: binding.created_at,
        binding_event_ref: current.binding_event_ref.to_string(),
    })
}

fn direct_slot_coordinates(
    pair_key: Hash,
    slot: &coland_storage::DirectConversationFoundingSlotRecord,
) -> Result<DirectConversationCoordinates, AppError> {
    Ok(DirectConversationCoordinates {
        pair_key,
        realm_id: RealmId::new(slot.realm_id.clone())
            .map_err(|error| AppError::internal(format!("stored direct Realm id: {error}")))?,
        main_strand_id: StrandId::new(slot.main_strand_id.clone())
            .map_err(|error| AppError::internal(format!("stored direct Strand id: {error}")))?,
        binding_event_ref: None,
    })
}

fn account_response(account: AccountRecord, state: &AppState) -> ColandAccountRegisterOutcome {
    let lifecycle_state = state.account_lifecycle_state(account.principal_id.as_str());
    ColandAccountRegisterOutcome {
        handle: account.handle(),
        principal_id: account.principal_id,
        display_name: account.display_name,
        state: lifecycle_state,
        created_at: account.created_at,
    }
}

async fn put_account_device_placeholder(
    state: &AppState,
    actor: &str,
    display_name: Option<String>,
    device_id: &str,
) -> Result<(), AppError> {
    let registered_at = now();
    // Device-identity B-model: account registration only creates an
    // unverified placeholder. `ak.device.authorize` is still the only path
    // that can attach a device public key and mark the device verified.
    let device = DeviceIdentity {
        actor_id: actor.to_owned(),
        device_id: device_id.to_owned(),
        display_name: display_name.clone(),
        verification_state: "unverified".to_owned(),
        payload: json!({
            "device_id": device_id,
            "display_name": display_name,
            "verification": "unverified",
            "registered_with_account": true,
        }),
        created_at: registered_at,
        updated_at: registered_at,
        revoked_at: None,
    };
    state
        .identities()
        .save_device_if_absent(device)
        .await
        .map(|_| ())
        .map_err(|error| AppError::internal(error.to_string()))
}

/// The closed read-side inputs of the device lifecycle fold,
/// `crypto-media/device-lifecycle.md` §5.5.3.
#[derive(Clone, Copy, Debug)]
struct DeviceStatusFoldInputs {
    revoked: bool,
    generation_fenced: bool,
    revocation_pending: bool,
    expired: bool,
}

/// Apply the fixed §5.5.3 precedence: the first holding condition wins, so
/// two implementations fold the same inputs to the same value.
fn fold_device_summary_status(inputs: DeviceStatusFoldInputs) -> DeviceSummaryStatus {
    if inputs.revoked {
        DeviceSummaryStatus::Revoked
    } else if inputs.generation_fenced {
        DeviceSummaryStatus::GenerationFenced
    } else if inputs.revocation_pending {
        DeviceSummaryStatus::RevocationPending
    } else if inputs.expired {
        DeviceSummaryStatus::Expired
    } else {
        DeviceSummaryStatus::Active
    }
}

async fn account_device_summaries(
    state: &AppState,
    actor: &str,
) -> Result<Vec<AccountDeviceSummary>, AppError> {
    let current_generation = super::device_generation::current_device_generation(state, actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let devices = state
        .identities()
        .devices_for_actor(actor)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let mut summaries = Vec::with_capacity(devices.len());
    for device in devices {
        summaries
            .push(account_device_summary(state, actor, device, current_generation.as_ref()).await?);
    }
    Ok(summaries)
}

async fn account_device_summary(
    state: &AppState,
    _actor: &str,
    device: DeviceIdentity,
    current_generation: Option<&super::device_generation::DeviceGenerationView>,
) -> Result<AccountDeviceSummary, AppError> {
    let device_id = DeviceId::new(device.device_id.clone()).map_err(|error| {
        AppError::internal(format!(
            "stored device_id `{}` is invalid: {error}",
            device.device_id
        ))
    })?;
    let display_name = device
        .display_name
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty());
    let authorized_event_id = device
        .payload
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .map(|value| EventId::new(value.to_owned()))
        .transpose()
        .map_err(|error| {
            AppError::internal(format!("stored authorization Event id is invalid: {error}"))
        })?;
    let accepted = match authorized_event_id.as_ref() {
        Some(event_id) => state
            .persistence()
            .committed_event(event_id)
            .await
            .map_err(|error| {
                AppError::internal(format!("device authorization Commit unavailable: {error}"))
            })?,
        None => None,
    };
    if accepted.as_ref().is_some_and(|record| {
        authorized_event_id.as_ref() != Some(&record.commit.event_ref)
            || record.event.event_id != record.commit.event_ref
            || record.event.kind != arkret_wire::EventKind::DeviceAuthorize
    }) {
        return Err(AppError::internal(
            "device authorization Commit does not bind the accepted DeviceAuthorize Event",
        ));
    }
    let generation_fenced = current_generation.is_some_and(|current| {
        device
            .payload
            .get("authorized_generation_ref")
            .and_then(Value::as_u64)
            != Some(current.current_ref)
    });
    let expired = device
        .payload
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|value| value.with_timezone(&chrono::Utc) <= now());
    // Coland does not read the `device_revocation_proposals` keyed set here
    // yet, so that input is false rather than derived from gate rows.
    let status = fold_device_summary_status(DeviceStatusFoldInputs {
        revoked: device.revoked_at.is_some(),
        generation_fenced,
        revocation_pending: false,
        expired,
    });
    let (verification_state, verification_source) =
        coland_services::identity::fold_device_verification_checkpoint(
            device.verification_state.as_str(),
            accepted.is_some(),
            device
                .payload
                .get("authorization_binding_kind")
                .and_then(Value::as_str),
            generation_fenced,
        );
    let authorized_event_ref = if verification_state == DeviceSummaryVerificationState::Unresolved {
        None
    } else {
        Some(
            accepted
                .as_ref()
                .ok_or_else(|| {
                    AppError::internal("verified device has no accepted authorization Commit")
                })?
                .commit
                .event_ref
                .clone(),
        )
    };
    let summary = AccountDeviceSummary {
        device_id,
        status,
        verification_state,
        verification_source,
        display_name,
        authorized_event_ref,
        authorized_at: accepted.as_ref().map(|record| record.commit.committed_at),
        last_seen_at: None,
        revoked_at: device.revoked_at,
        // A revoke target contains only the committed tombstone and cannot
        // reconstruct the typed pending/revoked current result's acceptance
        // sequence. `validate` below fails closed for revoked devices.
        revocation_states: None,
    };
    summary
        .validate()
        .map_err(|error| AppError::internal(format!("device summary is invalid: {error}")))?;
    Ok(summary)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn device_status_fold_takes_the_first_condition_in_registered_precedence() {
        for mask in 0u8..16 {
            let inputs = DeviceStatusFoldInputs {
                revoked: mask & 1 != 0,
                generation_fenced: mask & 2 != 0,
                revocation_pending: mask & 4 != 0,
                expired: mask & 8 != 0,
            };
            let expected = [
                (inputs.revoked, DeviceSummaryStatus::Revoked),
                (
                    inputs.generation_fenced,
                    DeviceSummaryStatus::GenerationFenced,
                ),
                (
                    inputs.revocation_pending,
                    DeviceSummaryStatus::RevocationPending,
                ),
                (inputs.expired, DeviceSummaryStatus::Expired),
            ]
            .into_iter()
            .find_map(|(holds, status)| holds.then_some(status))
            .unwrap_or(DeviceSummaryStatus::Active);
            assert_eq!(fold_device_summary_status(inputs), expected, "{inputs:?}");
        }
    }

    #[test]
    fn generation_fence_outranks_expiry() {
        let status = fold_device_summary_status(DeviceStatusFoldInputs {
            revoked: false,
            generation_fenced: true,
            revocation_pending: false,
            expired: true,
        });
        assert_eq!(status, DeviceSummaryStatus::GenerationFenced);
    }

    fn projection_body_json() -> Value {
        json!({
            "principal_id": "ak:did_core:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x",
            "did": "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:alice.example:webvh:alice",
            "display_name": "Alice",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001"
        })
    }

    #[test]
    fn account_projection_body_accepts_only_matching_verified_did() {
        let body: AccountProjectionRequestBody =
            serde_json::from_value(projection_body_json()).unwrap();
        body.validate().unwrap();

        let mut mismatched = projection_body_json();
        mismatched["principal_id"] = json!("ak:did_core:webvh:z6MkmismatchedPrincipalScid");
        let body: AccountProjectionRequestBody = serde_json::from_value(mismatched).unwrap();
        assert!(body.validate().is_err());
    }

    #[test]
    fn account_projection_body_is_closed_and_rejects_public_registration_branches() {
        for field in ["proof", "identity_creation", "policy_evidence"] {
            let mut value = projection_body_json();
            value[field] = json!({});
            assert!(
                serde_json::from_value::<AccountProjectionRequestBody>(value).is_err(),
                "deployment-private projection DTO must reject {field}"
            );
        }

        let mut did_url = projection_body_json();
        did_url["did"] = json!(
            "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:alice.example#device-1"
        );
        assert!(
            serde_json::from_value::<AccountProjectionRequestBody>(did_url).is_err(),
            "did must not contain DID URL path, query, or fragment components"
        );
    }

    #[test]
    fn agent_direct_basis_uses_provisioning_and_runtime_key_facts() {
        let created_at = chrono::Utc::now();
        let mut record = AgentPairingState::new(
            "did:web:agents.example:assistant".to_owned(),
            "did:web:alice.example".to_owned(),
            "ak:realm:AXqIXbu56hFXteZXtkBsqJxy_puV4mhSv1U0ZkUldxAL".to_owned(),
            arkret_wire::DidUrl::new("did:web:agents.example:assistant#managed-controller")
                .unwrap(),
            AgentLifecycleState::Active,
            created_at,
        );
        record.provision_event_refs = Some(json!({
            "provision_event_id": "ak:event:AUvEs_-d1tc81yDszBZAVWapgIr3Gs6ofbmtZSLQNejL"
        }));
        record.authorized_event_ref =
            Some("ak:event:AVeCvdcuh1hDJWwYlZJb_1yRzWQwN1-pXxgZYTyd7BGT".to_owned());

        let basis = agent_direct_authorization_basis_from_record(&record).unwrap();
        assert_eq!(
            basis.kind,
            arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::AgentController
        );
        assert_eq!(
            basis
                .event_refs
                .iter()
                .map(EventId::as_str)
                .collect::<Vec<_>>(),
            vec![
                "ak:event:AUvEs_-d1tc81yDszBZAVWapgIr3Gs6ofbmtZSLQNejL",
                "ak:event:AVeCvdcuh1hDJWwYlZJb_1yRzWQwN1-pXxgZYTyd7BGT",
            ]
        );

        record.authorized_event_ref = None;
        assert!(agent_direct_authorization_basis_from_record(&record).is_none());
    }

    #[test]
    fn account_localpart_uses_the_handle_preparation_profile() {
        assert_eq!(
            normalize_account_localpart_for_request("ＡＬＩＣＥ").unwrap(),
            "alice"
        );
        assert_eq!(
            normalize_account_localpart_for_request("小明").unwrap(),
            "小明"
        );
    }

    #[test]
    fn did_host_candidate_extracts_webvh_host_not_scid() {
        assert_eq!(
            did_host_candidate(
                "did:webvh:z2dmjYwAPJzv5CZsnAzt8auVZRn1GfuxhpK2t3Q3K3rj4B1x:local.host:webvh:alice"
            )
            .as_deref(),
            Some("local.host")
        );
    }
}
