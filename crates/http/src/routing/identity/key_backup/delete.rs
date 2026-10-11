//! High-risk key-backup delete authority (`key-management.md` §7.8 / §7.8.1).
//!
//! # Why this is not "verify a proof"
//!
//! §7.8 judged the previous shape dead: a `DetachedJws` proof over a
//! locally-invented transcript, plus a `Development` branch whose "proof" was
//! an unauthenticated actor/backup string. Neither
//! carried server-issued freshness, so both were replayable for as long as the
//! envelope existed.
//!
//! The replacement is a three-step protocol, and the steps only work together:
//!
//! 1. the client asks for a challenge (`issue_key_backup_delete_challenge`). The server mints every
//!    freshness value — §7.8.1 forbids accepting a caller-minted nonce — and stores it durably,
//!    single-use, with a TTL of at most 300 s.
//! 2. the client signs the **canonical delete-intent transcript**, which embeds every field of that
//!    challenge verbatim. So a replay, an expired challenge, a different backup, a different
//!    audience or a different service fails at signature verification as well as at challenge
//!    lookup — two independent gates, not one.
//! 3. the server verifies one of the three closed authority branches and consumes the challenge in
//!    the same step as the delete.
//!
//! An ordinary current-device session proof is deliberately **not** a fourth
//! branch (§7.8): a caller holding only that is limited to envelopes that are
//! already expired and outside the active series.

use arkret_models_crypto::{
    KeyBackupDeleteProof, KeyBackupDeleteQuorumSignature, KeysBackupsDeleteChallenge,
    KeysBackupsDeleteRequestBody, KeysBackupsIssueDeleteChallengeRequestBody,
};
use arkret_signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use arkret_wire::{Base64UrlString, NonEmptyString, PayloadProof, ServiceOperationId};
use chrono::{DateTime, Duration, Utc};
use rand::RngExt as _;

use super::*;

/// Section 7.8.1 limits the TTL to 300 seconds.
pub(super) const DELETE_CHALLENGE_TTL_SECONDS: i64 = 300;

/// The operation every delete challenge and transcript is bound to.
pub(super) const KEY_BACKUP_DELETE_OPERATION: &str =
    ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_DELETE_V1;

/// How long the `(account_id, backup_id, request_id)` terminal outcome is
/// replayable (§7.8.1 step 4). Matches the generic `Idempotency-Key` TTL.
pub(super) const KEY_BACKUP_DELETE_IDEMPOTENCY_TTL_SECONDS: i64 = 86_400;

/// The `ak:` prefix every recovery session id carries, mirrored from the unlock
/// path so both agree on what a session reference looks like.
const RECOVERY_SESSION_ID_PREFIX: &str = "ak:recovery_session:";

/// The service origin a challenge is bound to.
///
/// Shared with the device-pairing gate so one deployment cannot present two
/// different audiences depending on which endpoint minted the value.
fn service_audience(state: &AppState) -> Result<String, AppError> {
    let url = reqwest::Url::parse(&state.config().public_base_url)
        .map_err(|error| AppError::internal(format!("public_base_url is invalid: {error}")))?;
    let origin = url.origin().ascii_serialization();
    if origin == "null" {
        return Err(AppError::internal(
            "public_base_url has no origin for the key-backup delete challenge",
        ));
    }
    Ok(origin)
}

fn random_base64url(bytes: usize) -> Base64UrlString {
    let mut buffer = vec![0u8; bytes];
    rand::rng().fill(buffer.as_mut_slice());
    Base64UrlString::new(URL_SAFE_NO_PAD.encode(&buffer))
        .expect("base64url of random bytes is a valid Base64UrlString")
}

/// `POST /_arkret/self/keys/backups/{backup_id}/delete-challenge`.
///
/// Owning the backup is checked here rather than only at DELETE time so an
/// unrelated principal cannot use this endpoint to learn whether a backup id
/// exists.
#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.backups.command.issue_delete_challenge",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.keys.backups.command.issue_delete_challenge.v1")
)]
pub(super) async fn issue_key_backup_delete_challenge(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    body: JsonBody<KeysBackupsIssueDeleteChallengeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsDeleteChallenge> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let backup_id = backup_id.into_inner();
    let request_id = body.into_inner().request_id;
    require_owned_backup(state, &backup_id, &session.actor).await?;

    let principal_id =
        arkret_identifiers::DidCoreId::new(session.actor.clone()).map_err(|error| {
            AppError::capability_denied(format!("authenticated actor is not a valid DID: {error}"))
        })?;
    let typed_backup_id = BackupId::new(backup_id.clone())
        .map_err(|error| AppError::param_invalid(format!("backup_id is invalid: {error}")))?;
    let service_id = arkret_identifiers::DidCoreId::new(state.service_id().clone())
        .map_err(|error| AppError::internal(format!("service_id is not a valid DID: {error}")))?;
    let audience = NonEmptyString::new(service_audience(state)?)
        .map_err(|error| AppError::internal(format!("service audience is invalid: {error}")))?;

    let issued_at = Utc::now();
    let challenge = KeysBackupsDeleteChallenge {
        challenge_id: random_base64url(16),
        // Two independent freshness values, as §7.8.1 requires: forging the
        // transcript needs both, and neither is client-supplied.
        challenge: random_base64url(32),
        nonce: random_base64url(16),
        operation: KEY_BACKUP_DELETE_OPERATION.to_owned(),
        account_id: arkret_wire::AccountId::new(principal_id, state.service_core_id()),
        backup_id: typed_backup_id,
        audience,
        service_id,
        request_id,
        issued_at,
        expires_at: issued_at + Duration::seconds(DELETE_CHALLENGE_TTL_SECONDS),
    };

    let record = coland_services::identity::KeyBackupDeleteChallengeRecord {
        challenge_id: challenge.challenge_id.as_str().to_owned(),
        account_id: challenge.account_id.clone(),
        backup_id: challenge.backup_id.as_str().to_owned(),
        request_id: challenge.request_id.as_str().to_owned(),
        challenge: serde_json::to_value(&challenge).map_err(|error| {
            AppError::internal(format!("delete challenge is not serializable: {error}"))
        })?,
        issued_at: challenge.issued_at,
        expires_at: challenge.expires_at,
        consumed_at: None,
    };
    let issued = state
        .key_backups()
        .issue_delete_challenge(record, issued_at)
        .await
        .map_err(|error| {
            AppError::internal(format!("delete challenge could not be issued: {error}"))
        })?;
    // The store returns the *held* challenge when one is still valid for this
    // `(account_id, backup_id, request_id)`, so a retry of this call keeps
    // returning the challenge the client may already be signing.
    let issued: KeysBackupsDeleteChallenge =
        serde_json::from_value(issued.challenge).map_err(|error| {
            AppError::internal(format!("stored delete challenge is corrupt: {error}"))
        })?;
    json_ok(issued)
}

async fn require_owned_backup(
    state: &AppState,
    backup_id: &str,
    actor_id: &str,
) -> Result<Value, AppError> {
    let account_actor = local_backup_actor(state, actor_id)?;
    state
        .key_backups()
        .backup(backup_id)
        .await
        .map_err(|error| AppError::internal(format!("key backup lookup failed: {error}")))?
        .filter(|backup| backup_actor_matches(backup, &account_actor))
        .ok_or_else(|| AppError::not_found("key backup not found"))
}

/// `keys_backups_delete_proof` is exactly one of `recovery_unlock`,
/// `device_quorum` or `trusted_recovery_service` (key-management.md §7.8.1);
/// an ordinary current-device proof is not a fourth branch.
pub(super) fn require_high_risk_delete_proof(
    body: &KeysBackupsDeleteRequestBody,
) -> Result<(), AppError> {
    match body.proof {
        KeyBackupDeleteProof::CurrentDevice { .. } => Err(current_device_delete_proof_rejected()),
        KeyBackupDeleteProof::RecoverySession { .. }
        | KeyBackupDeleteProof::DeviceQuorum { .. } => Ok(()),
    }
}

fn current_device_delete_proof_rejected() -> AppError {
    AppError::param_invalid(
        "key backup delete proof must be recovery_unlock, device_quorum or \
         trusted_recovery_service; current_device is not a delete authority",
    )
}

/// The verified challenge a DELETE is authorized against.
pub(super) struct AuthorizedKeyBackupDelete {
    pub(super) challenge_id: String,
    pub(super) gate: coland_storage::KeyBackupDeleteGate,
    pub(super) recovery_session_id: Option<String>,
    pub(super) proof_branch: &'static str,
}

/// Verify a DELETE request against its challenge and one authority branch.
///
/// Does **not** consume the challenge: consumption belongs in the same step as
/// the delete it authorizes, so a verified-but-failed delete does not burn the
/// challenge. See [`consume_key_backup_delete_challenge`].
pub(super) async fn authorize_key_backup_delete(
    state: &AppState,
    body: &KeysBackupsDeleteRequestBody,
    backup_id: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<AuthorizedKeyBackupDelete, AppError> {
    let challenge = load_valid_challenge(state, body, backup_id, actor_id, now).await?;
    let pointers = super::listing::active_pointers(state, &challenge.account_id).await?;
    let transcript = challenge.delete_intent_transcript(body.reason.as_deref());
    let canonical = arkret_canonical::canonical_json_bytes(&transcript).map_err(|error| {
        AppError::internal(format!(
            "delete-intent transcript is not canonical: {error}"
        ))
    })?;
    let expected_digest = challenge
        .delete_intent_digest(body.reason.as_deref())
        .map_err(|error| AppError::internal(format!("delete-intent digest failed: {error}")))?;

    let mut expected_policy = None;
    let proof_branch = match &body.proof {
        KeyBackupDeleteProof::CurrentDevice { .. } => {
            return Err(current_device_delete_proof_rejected());
        }
        KeyBackupDeleteProof::RecoverySession {
            recovery_session_id,
            proof,
        } => {
            verify_recovery_unlock_delete(
                state,
                &challenge,
                recovery_session_id.as_str(),
                proof,
                &expected_digest,
                &canonical,
            )
            .await?;
            "recovery_unlock"
        }
        KeyBackupDeleteProof::DeviceQuorum {
            threshold,
            signatures,
        } => {
            expected_policy = Some(
                verify_device_quorum_delete(
                    state,
                    &challenge,
                    *threshold,
                    signatures,
                    &expected_digest,
                    &canonical,
                )
                .await?,
            );
            "device_quorum"
        }
    };

    let mut quorum_devices = Vec::new();
    if let KeyBackupDeleteProof::DeviceQuorum { signatures, .. } = &body.proof {
        quorum_devices.extend(
            signatures
                .iter()
                .map(|contribution| contribution.device_id.clone()),
        );
    }
    quorum_devices.sort_unstable();
    quorum_devices.dedup();
    Ok(AuthorizedKeyBackupDelete {
        gate: coland_storage::KeyBackupDeleteGate {
            basis: coland_storage::KeyBackupPointerBasis {
                account_id: pointers.account_id,
                secret_storage: pointers.secret_storage,
            },
            quorum_devices,
            expected_policy,
        },
        challenge_id: challenge.challenge_id.as_str().to_owned(),
        recovery_session_id: match &body.proof {
            KeyBackupDeleteProof::RecoverySession {
                recovery_session_id,
                ..
            } => Some(recovery_session_id.as_str().to_owned()),
            KeyBackupDeleteProof::CurrentDevice { .. }
            | KeyBackupDeleteProof::DeviceQuorum { .. } => None,
        },
        proof_branch,
    })
}

/// Consume the challenge. `false` means a concurrent request already consumed
/// it, which is the single-use guarantee doing its job.
pub(super) async fn consume_key_backup_delete_challenge(
    state: &AppState,
    authorized: &AuthorizedKeyBackupDelete,
    backup: Value,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let consumed = state
        .key_backups()
        .consume_delete_challenge(
            &authorized.gate,
            &authorized.challenge_id,
            backup,
            authorized.recovery_session_id.as_deref(),
            now,
        )
        .await
        .map_err(|error| {
            AppError::internal(format!("delete challenge could not be consumed: {error}"))
        })?;
    if consumed {
        return Ok(());
    }
    Err(
        AppError::conflict("key backup delete challenge was already consumed")
            .with_wire_code("failed_precondition")
            .with_reason_detail("single-use delete challenge (key-management.md §7.8.1)"),
    )
}

/// Every check §7.8.1 step 3 puts *before* the proof branch: replay, expiry, a
/// different path, a different audience, a different service.
async fn load_valid_challenge(
    state: &AppState,
    body: &KeysBackupsDeleteRequestBody,
    backup_id: &str,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<KeysBackupsDeleteChallenge, AppError> {
    let record = state
        .key_backups()
        .delete_challenge(body.challenge_id.as_str())
        .await
        .map_err(|error| AppError::internal(format!("delete challenge lookup failed: {error}")))?
        .ok_or_else(|| AppError::capability_denied("key backup delete challenge is unknown"))?;
    if record.consumed_at.is_some() {
        return Err(AppError::capability_denied(
            "key backup delete challenge was already consumed",
        ));
    }
    if record.expires_at <= now {
        return Err(AppError::capability_denied(
            "key backup delete challenge has expired",
        ));
    }
    let challenge: KeysBackupsDeleteChallenge =
        serde_json::from_value(record.challenge).map_err(|error| {
            AppError::internal(format!("stored delete challenge is corrupt: {error}"))
        })?;
    let caller_account = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(actor_id.to_owned()).map_err(|error| {
            AppError::capability_denied(format!("authenticated actor is invalid: {error}"))
        })?,
        state.service_core_id(),
    );
    if challenge.account_id != caller_account {
        return Err(AppError::capability_denied(
            "key backup delete challenge belongs to another account",
        ));
    }
    if challenge.backup_id.as_str() != backup_id {
        return Err(AppError::capability_denied(
            "key backup delete challenge was issued for another backup",
        ));
    }
    if challenge.request_id != body.request_id {
        return Err(AppError::capability_denied(
            "key backup delete challenge was issued for another request_id",
        ));
    }
    if challenge.operation != KEY_BACKUP_DELETE_OPERATION {
        return Err(AppError::capability_denied(
            "key backup delete challenge was issued for another operation",
        ));
    }
    if challenge.audience.as_str() != service_audience(state)? {
        return Err(AppError::capability_denied(
            "key backup delete challenge was issued for another audience",
        ));
    }
    if challenge.service_id.as_str() != state.service_id().as_str() {
        return Err(AppError::capability_denied(
            "key backup delete challenge was issued by another service",
        ));
    }
    Ok(challenge)
}

/// Shape checks every branch's `PayloadProof` shares: it must commit to *this*
/// transcript and have been created inside the challenge window.
fn check_proof_envelope(
    challenge: &KeysBackupsDeleteChallenge,
    proof: &PayloadProof,
    expected_digest: &arkret_identifiers::Hash,
) -> Result<(), AppError> {
    if proof.payload_digest != *expected_digest {
        return Err(AppError::capability_denied(
            "key backup delete proof does not cover the canonical delete-intent transcript",
        ));
    }
    // §7.8.1: `created_at` MUST fall inside the challenge window. Without this a
    // signature could predate the challenge it claims to answer.
    if proof.created_at < challenge.issued_at || proof.created_at > challenge.expires_at {
        return Err(AppError::capability_denied(
            "key backup delete proof was not created inside the challenge window",
        ));
    }
    Ok(())
}

/// `recovery_unlock`: bind the delete proof to the exact verified, unconsumed
/// recovery session and resolve the signer only from the policy snapshot frozen
/// into that session.
async fn verify_recovery_unlock_delete(
    state: &AppState,
    challenge: &KeysBackupsDeleteChallenge,
    recovery_session_id: &str,
    proof: &PayloadProof,
    expected_digest: &arkret_identifiers::Hash,
    canonical: &[u8],
) -> Result<(), AppError> {
    check_proof_envelope(challenge, proof, expected_digest)?;
    if !recovery_session_id.starts_with(RECOVERY_SESSION_ID_PREFIX) {
        return Err(AppError::param_invalid(
            "key backup delete recovery_session_id must start with ak:recovery_session:",
        ));
    }
    let session = state
        .recovery_sessions()
        .session(recovery_session_id)
        .await
        .map_err(|error| AppError::internal(format!("recovery session lookup failed: {error}")))?
        .ok_or_else(|| {
            AppError::capability_denied("key backup delete recovery session is unknown")
        })?;
    super::super::recovery::validate_frozen_session_policy(state, &session, None).await?;
    ensure_recovery_unlock_session_eligible(
        &session.principal_id,
        &session.station_id,
        session.state,
        session.transaction_id.as_deref(),
        session.created_at,
        session.expires_at,
        &challenge.account_id,
        proof.created_at,
    )?;
    let key = super::super::recovery::recovery_session_unlock_verifying_key(
        &session,
        proof.verification_method.as_str(),
    )?;
    if !verify_detached_jws(&key, canonical, &proof.jws) {
        return Err(AppError::capability_denied(
            "recovery-unlock key-backup deletion proof is invalid",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn ensure_recovery_unlock_session_eligible(
    principal_id: &arkret_wire::DidCoreId,
    station_id: &arkret_wire::DidCoreId,
    lifecycle: coland_storage::RecoverySessionLifecycle,
    transaction_id: Option<&str>,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    account_id: &arkret_wire::AccountId,
    proof_created_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), AppError> {
    if principal_id != &account_id.principal_id || station_id != &account_id.station_id {
        return Err(AppError::capability_denied(
            "key backup delete recovery session belongs to another account",
        ));
    }
    if lifecycle != coland_storage::RecoverySessionLifecycle::Verified || transaction_id.is_some() {
        return Err(AppError::capability_denied(
            "key backup delete recovery session is not verified and unconsumed",
        ));
    }
    if proof_created_at < created_at || proof_created_at > expires_at {
        return Err(AppError::capability_denied(
            "key backup delete recovery session is expired for this proof",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod recovery_unlock_session_tests {
    use super::*;

    fn account(principal: &str, station: &str) -> arkret_wire::AccountId {
        arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(principal.to_owned()).unwrap(),
            arkret_wire::DidCoreId::new(station.to_owned()).unwrap(),
        )
    }

    #[test]
    fn recovery_unlock_delete_requires_the_exact_verified_live_session() {
        let owner = account(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:station.example",
        );
        let other = account(
            "ak:did_core:web:bob.example",
            "ak:did_core:web:station.example",
        );
        let created_at = "2026-09-27T00:00:00.000Z".parse().unwrap();
        let expires_at = "2026-09-27T00:05:00.000Z".parse().unwrap();
        let proof_at = "2026-09-27T00:01:00.000Z".parse().unwrap();
        let check =
            |account_id: &arkret_wire::AccountId, lifecycle, transaction_id, proof_created_at| {
                ensure_recovery_unlock_session_eligible(
                    &owner.principal_id,
                    &owner.station_id,
                    lifecycle,
                    transaction_id,
                    created_at,
                    expires_at,
                    account_id,
                    proof_created_at,
                )
            };
        check(
            &owner,
            coland_storage::RecoverySessionLifecycle::Verified,
            None,
            proof_at,
        )
        .unwrap();
        assert!(
            check(
                &other,
                coland_storage::RecoverySessionLifecycle::Verified,
                None,
                proof_at,
            )
            .is_err()
        );
        assert!(
            check(
                &owner,
                coland_storage::RecoverySessionLifecycle::Pending,
                None,
                proof_at,
            )
            .is_err()
        );
        assert!(
            check(
                &owner,
                coland_storage::RecoverySessionLifecycle::Verified,
                Some("ak:security_transaction:consumed"),
                proof_at,
            )
            .is_err()
        );
        assert!(
            check(
                &owner,
                coland_storage::RecoverySessionLifecycle::Verified,
                None,
                "2026-09-27T00:05:00.001Z".parse().unwrap(),
            )
            .is_err()
        );
    }
}

/// `device_quorum`: deduplicate by `device_id`, verify every signature over the
/// same transcript, and require the deduplicated valid count to reach the
/// principal's currently accepted recovery-policy `k` — which the request's
/// `threshold` MUST itself equal.
async fn verify_device_quorum_delete(
    state: &AppState,
    challenge: &KeysBackupsDeleteChallenge,
    threshold: u32,
    signatures: &[KeyBackupDeleteQuorumSignature],
    expected_digest: &arkret_identifiers::Hash,
    canonical: &[u8],
) -> Result<Value, AppError> {
    let accepted = current_recovery_policy(state, &challenge.account_id).await?;
    let policy_k =
        crate::routing::identity::device_signing::policy_device_quorum_threshold(&accepted)
            .ok_or_else(|| AppError::capability_denied("accepted policy has no device quorum"))?;
    // Equality, not `>=`: §7.8.1 says the request threshold MUST equal the
    // policy `k`, so a caller cannot declare a lower bar and cannot silently
    // pass a stale higher one either.
    if threshold != policy_k {
        return Err(AppError::capability_denied(format!(
            "key backup delete quorum threshold {threshold} does not equal the accepted recovery \
             policy k={policy_k}"
        )));
    }
    let policy: arkret_models_crypto::RecoveryPolicy =
        serde_json::from_value(accepted.raw_payload.clone())
            .map_err(|e| AppError::capability_denied(format!("accepted policy invalid: {e}")))?;
    let Some(arkret_models_crypto::RecoveryMethod::DeviceQuorum { member_ids, .. }) =
        policy.methods.iter().find(|method| {
            matches!(
                method,
                arkret_models_crypto::RecoveryMethod::DeviceQuorum { .. }
            )
        })
    else {
        return Err(AppError::capability_denied(
            "device quorum method not enabled",
        ));
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut valid = 0u32;
    for contribution in signatures {
        check_proof_envelope(challenge, &contribution.proof, expected_digest)?;
        if !seen.insert(contribution.device_id.as_str().to_owned()) {
            return Err(AppError::capability_denied(
                "key backup delete quorum repeats a device_id",
            ));
        }
        if !member_ids.contains(&contribution.device_id) {
            return Err(AppError::capability_denied(
                "device is not a member of the accepted quorum",
            ));
        }
        let key = crate::jws_verify::resolve_principal_authorized_device_key_with_account_authority_async(
            contribution.proof.verification_method.as_str(), &challenge.account_id, &contribution.device_id, state,
        ).await.map_err(|e| AppError::capability_denied(e.to_string()))?;
        if !verify_detached_jws(&key, canonical, &contribution.proof.jws) {
            return Err(AppError::capability_denied(
                "key backup delete quorum signature is invalid",
            ));
        }
        valid += 1;
    }
    if valid < policy_k {
        return Err(AppError::capability_denied(format!(
            "key backup delete quorum has {valid} valid signatures, below the accepted recovery \
             policy k={policy_k}"
        )));
    }
    Ok(accepted.raw_payload)
}

fn verify_detached_jws(key: &ed25519_dalek::VerifyingKey, canonical: &[u8], jws: &str) -> bool {
    let material = PublicKeyMaterial::Ed25519Raw {
        bytes: key.to_bytes().to_vec(),
    };
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(jws, canonical, &material)
        .is_ok()
}

async fn current_recovery_policy(
    state: &AppState,
    account_id: &arkret_wire::AccountId,
) -> Result<coland_services::identity::RecoveryPolicyState, AppError> {
    state
        .recovery_policies()
        .active_policy(account_id)
        .await
        .map_err(|error| AppError::internal(format!("recovery policy lookup failed: {error}")))?
        .ok_or_else(|| {
            AppError::capability_denied(
                "no accepted recovery policy for this account (key-management.md §7.8.1)",
            )
        })
}

pub(super) fn ensure_key_backup_delete_is_series_tail(
    actor_id: &arkret_wire::ActorId,
    backup: &Value,
    owned_backups: &[Value],
) -> Result<(), AppError> {
    let series_id = backup
        .get("series_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let series_seq = backup
        .get("series_seq")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    if series_id.is_empty() {
        return Ok(());
    }
    for existing in owned_backups {
        if !backup_actor_matches(existing, actor_id) {
            continue;
        }
        if existing.get("series_id").and_then(Value::as_str) != Some(series_id) {
            continue;
        }
        if existing
            .get("series_seq")
            .and_then(Value::as_u64)
            .is_some_and(|seq| seq > series_seq)
        {
            // key-management.md §7.8: active-series non-tail envelopes MUST
            // NOT be individually deleted. No dedicated registry code exists
            // for this rule, so surface the canonical `failed_precondition`
            // with the rule spelled out in the diagnostic detail.
            return Err(AppError::conflict(
                "key backup series non-tail envelopes cannot be individually deleted",
            )
            .with_wire_code("failed_precondition")
            .with_reason_detail(
                "active series non-tail delete forbidden (key-management.md §7.8)",
            ));
        }
    }
    Ok(())
}

pub(super) async fn ensure_key_backup_delete_allowed(
    state: &AppState,
    actor_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    let owned_backups = owned_key_backup_snapshot(state, actor_id).await?;
    ensure_key_backup_delete_is_series_tail(
        &local_backup_actor(state, actor_id)?,
        backup,
        &owned_backups,
    )
}
