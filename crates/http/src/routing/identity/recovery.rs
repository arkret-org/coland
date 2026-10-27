//! Recovery policy and recovery-session endpoints.
//!
//! Mounts recovery policy and durable recovery-transaction endpoints:
//!
//! - `GET /_arkret/root/identity/recovery-policy` — read the active recovery policy.
//! - `POST /_arkret/root/identity/recovery-policy` — persist + advance a recovery policy.
//!
//! Wire-level validation lands here (proof_kind enum, recovery_session
//! uuid pattern, expires/policy_version monotonicity,
//! `recovery_witness_revoke_lagging` freshness window).
//!
//! The implementation is split across sibling submodules under `recovery/`;
//! this module root keeps the routers, the shared `use` surface (re-exported to
//! submodules via `use super::*;`).

use std::collections::BTreeSet;

use arkret_identifiers::{Hash, PolicyId, RealmId, RecoverySessionId, TrustDomainId};
use arkret_models_crypto::{
    AuthoritySetAuthorizationIssuer, AuthoritySetAuthorizationRule, AuthoritySetIssuerRole,
    AuthoritySetPolicy, DidRootRecoveryTranscript, GenericRecoveryTranscript,
    PublicationAuthorityContext, RecoveryIdentityModel, RecoveryPolicy,
    RecoveryPolicyPublishRequestBody, RecoveryPolicyPublishResponseBody, RecoveryPolicyRef,
    RecoveryPolicyStatusView, RecoveryPolicySummary, RecoveryProofKind,
    RecoverySession as RecoverySessionState, RecoverySessionCreateRequestBody,
    RecoverySessionProofSubmitRequestBody, RecoverySessionProofSubmitResponseBody,
    RecoverySessionProofSummary as ProofSummary, RecoveryTranscriptProofBody, SecurityTransaction,
    SecurityTransactionContinueRequestBody, SecurityTransactionCreateRequestBody,
    TrustedRecoveryServiceProofBody, TrustedRecoveryServiceProofBodyWithSignature,
};
use arkret_wire::{
    AccountId, AuthoritySetId, AuthoritySetPolicyKind, Base64UrlString as Challenge, DeviceId,
    DidUrl, RequestId, SchemaId, SessionGrantId, TransactionId,
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use coland_http::error::{AppError, ErrorCode};
use coland_http::result::{JsonResult, json_ok};
use coland_services::ServiceError as PersistenceError;
use coland_services::identity::{
    RecoveryPolicyState, SecurityTransactionRecord, SessionIdentityState as SessionRecord,
};
use coland_storage::RecoverySessionLifecycle as SessionState;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use salvo::http::StatusCode;
use salvo::oapi::extract::{JsonBody, PathParam, QueryParam};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::{AuthArgs, append_audit_log};
use crate::state::AppState;

mod errors;
use errors::*;
mod policy_endpoints;
use policy_endpoints::*;
mod session_endpoints;
pub(crate) use session_endpoints::validate_frozen_session_policy;
use session_endpoints::*;
mod security_transaction_endpoints;
#[cfg(feature = "test-support")]
pub(crate) use security_transaction_endpoints::execute_rotation_erase_for_test;
pub(crate) use security_transaction_endpoints::sweep_rotation_worker;
use security_transaction_endpoints::*;
mod signatures;
use signatures::*;
mod validation;
use validation::*;
mod wire;
use wire::*;

/// Resolve the recovery-policy key that authenticated this recovery session.
/// Recovery-key possession is rooted in the signed policy, not in a DID
/// document that may contain no device methods after every device is lost.
pub(super) fn recovery_session_unlock_verifying_key(
    record: &coland_services::identity::RecoverySessionState,
    verification_method: &str,
) -> Result<VerifyingKey, AppError> {
    let summary = recovery_proof_summary(record).ok_or_else(|| {
        AppError::capability_denied("recovery session has no verified proof summary")
    })?;
    if summary.kind != RecoveryProofKind::RecoveryUnlock
        || summary.verification_method.as_ref().map(DidUrl::as_str) != Some(verification_method)
    {
        return Err(AppError::capability_denied(
            "key backup unlock signature is not identified by the recovery key accepted for the session",
        ));
    }
    let entry = resolve_recovery_key_entry(
        &record.policy_payload,
        verification_method,
        record.created_at,
    )?;
    decode_recovery_key_public_key(&entry)
}

/// Spec-canonical recovery surface mounted under `/_arkret/root/identity`.
///
/// The standard surface exposes recovery policy read/publish plus recovery
/// session lifecycle operations. A recovery receipt has no independent write
/// endpoint: it is the signed terminal artifact of a durable
/// `RecoveryTransaction`.
pub(super) fn protocol_router() -> Router {
    Router::with_path("identity")
        .push(
            Router::with_path("recovery-policy")
                .post(recovery_policy_put)
                .get(recovery_policy_get),
        )
        .push(
            Router::with_path("recovery-sessions").post(recovery_session_create), // C-P2 (REC-1)
        )
        .push(
            Router::with_path("recovery-sessions/{recovery_session_id}").get(recovery_session_get),
        )
        .push(
            Router::with_path("recovery-sessions/{recovery_session_id}/proofs")
                .post(recovery_session_proof_submit),
        )
}

/// Spec-canonical authenticated transaction coordinator surface mounted under
/// `/_arkret/self`.
pub(super) fn self_protocol_router() -> Router {
    Router::new()
        .push(Router::with_path("security-transactions").post(security_transaction_create))
        .push(
            Router::with_path("security-transactions/{transaction_id}")
                .get(security_transaction_get),
        )
        .push(
            Router::with_path("security-transactions/{transaction_id}/continue")
                .post(security_transaction_continue),
        )
}

pub(super) fn router() -> Router {
    Router::with_path("identity")
        .push(Router::with_path("recovery-policies").get(recovery_policies_get))
}

/// The method actually accepted for a durable session, never a caller assertion.
pub(super) fn recovery_session_proof_kind(
    record: &coland_services::identity::RecoverySessionState,
) -> Option<arkret_models_crypto::RecoveryProofKind> {
    recovery_proof_summary(record).map(|summary| summary.kind)
}
