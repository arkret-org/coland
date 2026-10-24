use coland_services::identity::RecoverySessionState as RecoverySessionServiceState;

use super::*;

fn verify_recovery_device_possession(
    payload: &RecoverySessionCreateRequestBody,
    session_grant_id: &str,
    session_grant_cnf_jkt: &str,
) -> Result<(), AppError> {
    let possession = arkret_models_crypto::RecoveryDevicePossessionTranscript {
        schema: arkret_models_crypto::RECOVERY_DEVICE_POSSESSION_DOMAIN.to_owned(),
        request_id: payload.request_id.clone(),
        session_grant_id: arkret_wire::SessionGrantId::new(session_grant_id.to_owned())
            .map_err(|error| AppError::internal(error.to_string()))?,
        session_grant_cnf_jkt: arkret_wire::Base64UrlString::new(session_grant_cnf_jkt.to_owned())
            .map_err(|error| crate::app_error!(SchemaViolation, error.to_string()))?,
        account_id: payload.account_id.clone(),
        requesting_device_id: payload.requesting_device_id.clone(),
        requesting_device_public_key_did: payload.requesting_device_public_key_did.clone(),
        trust_domain: payload.trust_domain.clone(),
        expected_recovery_policy_ref: payload.expected_recovery_policy_ref.clone(),
    };
    let possession_bytes = possession
        .signing_bytes()
        .map_err(|error| crate::app_error!(SchemaViolation, error.to_string()))?;
    let public_key = arkret_canonical::decode_ed25519_multibase(
        payload
            .requesting_device_public_key_did
            .as_str()
            .strip_prefix("did:key:")
            .unwrap_or(""),
    )
    .map_err(|error| crate::app_error!(SchemaViolation, error.to_string()))?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(payload.requesting_device_signature.as_str())
        .map_err(|error| crate::app_error!(SchemaViolation, error.to_string()))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .map_err(|error| crate::app_error!(SchemaViolation, error.to_string()))?;
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
        .map_err(|error| crate::app_error!(SchemaViolation, error.to_string()))?;
    key.verify_strict(&possession_bytes, &signature)
        .map_err(|_| {
            crate::app_error!(
                CapabilityDenied,
                "recovery replacement identity key possession proof is invalid"
            )
            .with_reason_code("recovery_evidence_unbound")
        })?;
    Ok(())
}

const RECOVERY_SESSION_TTL_SECS: i64 = 900;

fn recovery_method(
    policy: &RecoveryPolicy,
    kind: RecoveryProofKind,
) -> Option<&arkret_models_crypto::RecoveryMethod> {
    let expected = match kind {
        RecoveryProofKind::DidRoot => "did_root",
        RecoveryProofKind::RecoveryUnlock => "recovery_unlock",
        RecoveryProofKind::DeviceQuorum => "device_quorum",
        RecoveryProofKind::TrustedRecoveryService => "trusted_recovery_service",
    };
    policy
        .methods
        .iter()
        .find(|method| method.kind_str() == expected)
}

fn device_quorum_transcript_body(
    proof: &arkret_models_crypto::DeviceQuorumProofBodyWithSignatures,
) -> arkret_models_crypto::DeviceQuorumProofBody {
    arkret_models_crypto::DeviceQuorumProofBody {
        kind: proof.kind,
        challenge: proof.challenge.clone(),
        threshold: proof.threshold,
        signatures: proof
            .signatures
            .iter()
            .map(
                |signature| arkret_models_crypto::DeviceQuorumSignatureBody {
                    device_id: signature.device_id.clone(),
                    verification_method: signature.verification_method.clone(),
                    signature_algorithm: signature.signature_algorithm,
                },
            )
            .collect(),
    }
}

#[cfg(test)]
mod possession_tests {
    use ed25519_dalek::Signer as _;

    use super::*;

    #[test]
    fn create_possession_rejects_another_grant_or_replacement_key() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let transcript: arkret_models_crypto::RecoveryDevicePossessionTranscript = serde_json::from_value(serde_json::json!({
            "schema":"ak.identity.recovery_device_possession.v1",
            "request_id":"ak:request:01904100-0000-7000-8000-000000000001",
            "session_grant_id":"ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW",
            "session_grant_cnf_jkt":"A".repeat(43),
            "account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:station.example"},
            "requesting_device_id":"ak:device:01904100-0000-7000-8000-000000000071",
            "requesting_device_public_key_did":format!("did:key:{}",arkret_canonical::ed25519_pubkey_to_did_key_multibase(signer.verifying_key().as_bytes())),
            "trust_domain":"ak:trust_domain:01904100-0000-7000-8000-000000000001"
        })).unwrap();
        let signature = signer.sign(&transcript.signing_bytes().unwrap());
        let request = RecoverySessionCreateRequestBody {
            request_id: transcript.request_id.clone(),
            account_id: transcript.account_id.clone(),
            requesting_device_id: transcript.requesting_device_id.clone(),
            requesting_device_public_key_did: transcript.requesting_device_public_key_did.clone(),
            requesting_device_signature: arkret_wire::Base64UrlString::new(
                URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            )
            .unwrap(),
            trust_domain: transcript.trust_domain.clone(),
            expected_recovery_policy_ref: transcript.expected_recovery_policy_ref.clone(),
        };
        verify_recovery_device_possession(
            &request,
            transcript.session_grant_id.as_str(),
            &transcript.session_grant_cnf_jkt,
        )
        .unwrap();
        assert!(
            verify_recovery_device_possession(
                &request,
                transcript.session_grant_id.as_str(),
                &"B".repeat(43)
            )
            .is_err()
        );
        let mut changed = request;
        changed.requesting_device_public_key_did = arkret_wire::DidKey::new(format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                ed25519_dalek::SigningKey::from_bytes(&[43; 32])
                    .verifying_key()
                    .as_bytes()
            )
        ))
        .unwrap();
        assert!(
            verify_recovery_device_possession(
                &changed,
                transcript.session_grant_id.as_str(),
                &transcript.session_grant_cnf_jkt
            )
            .is_err()
        );
    }
}

fn generate_recovery_challenge() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

/// SOL-SEC-05 — constant-time string equality for recovery
/// challenge/commitment comparisons, so a timing side channel cannot leak how
/// many leading bytes of a security-relevant value matched.
fn constant_time_str_eq(left: &str, right: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    let left = left.as_bytes();
    let right = right.as_bytes();
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

// ── C-P2 (REC-1) recovery session lifecycle ──────────────────────────────
//
// A recovery session binds a *requesting device* to the principal's currently
// accepted recovery policy snapshot + a server-issued anti-replay challenge,
// and advances `pending -> verified` (or `rejected` / `expired`).
//
//   POST recovery-sessions                  — create (snapshot policy + challenge)
//   GET  recovery-sessions/{id}             — read status (principal-isolated)
//   POST recovery-sessions/{id}/proofs      — verify a proof (pending -> verified)
//
// C-P3 — `/proofs` cryptographically verifies the four closed recovery methods
// (did_root, recovery_unlock, device_quorum, trusted_recovery_service) over the
// canonical recovery-proof transcript and advances `pending -> verified` ONLY on
// success. Any other kind fails closed with 501
// `recovery_proof_kind_unimplemented` rather than silently leaving the session
// pending.
//
// Completion is exclusively owned by the bound RecoveryTransaction. There is
// no second public recovery-session completion command.

/// Derive the `proof_summary{kind, proof_digest, verification_method}` from a
/// session that has a recorded proof. `proof_digest` is the SHA-256 of the
/// canonical recovery-proof transcript, deterministically recomputed from the
/// stored session fields (no separate column needed).
pub(super) fn recovery_proof_summary(record: &RecoverySessionServiceState) -> Option<ProofSummary> {
    let proof = record.proof_payload.as_ref()?.get("proof")?.as_object()?;
    let kind = match proof.get("kind").and_then(Value::as_str)? {
        "did_root" => RecoveryProofKind::DidRoot,
        "recovery_unlock" => RecoveryProofKind::RecoveryUnlock,
        "device_quorum" => RecoveryProofKind::DeviceQuorum,
        "trusted_recovery_service" => RecoveryProofKind::TrustedRecoveryService,
        _ => return None,
    };
    let verification_method = proof
        .get("verification_method")
        .and_then(Value::as_str)
        .map(DidUrl::new)
        .transpose()
        .ok()?;
    let transcript = recovery_proof_summary_transcript(record, proof)?;
    let transcript_bytes = arkret_canonical::canonical_json_bytes(&transcript).ok()?;
    let proof_digest = Hash::new(arkret_canonical::sha256_digest(&transcript_bytes)).ok()?;
    Some(ProofSummary {
        kind,
        proof_digest,
        verification_method,
    })
}

fn recovery_proof_summary_transcript(
    record: &RecoverySessionServiceState,
    proof: &Map<String, Value>,
) -> Option<Value> {
    let kind = proof.get("kind").and_then(Value::as_str)?;
    match kind {
        "trusted_recovery_service" => {
            let proof_body = trusted_recovery_service_proof_body(proof).ok()?;
            let transcript = generic_recovery_proof_transcript(
                record,
                RecoveryTranscriptProofBody::TrustedRecoveryService(proof_body),
            )
            .ok()?;
            serde_json::to_value(transcript).ok()
        }
        "recovery_unlock" => {
            let proof_body = recovery_unlock_proof_body(proof).ok()?;
            let transcript = generic_recovery_proof_transcript(
                record,
                RecoveryTranscriptProofBody::RecoveryUnlock(proof_body),
            )
            .ok()?;
            serde_json::to_value(transcript).ok()
        }
        "device_quorum" => {
            let proof: arkret_models_crypto::DeviceQuorumProofBodyWithSignatures =
                serde_json::from_value(Value::Object(proof.clone())).ok()?;
            let body = device_quorum_transcript_body(&proof);
            serde_json::to_value(
                generic_recovery_proof_transcript(
                    record,
                    RecoveryTranscriptProofBody::DeviceQuorum(body),
                )
                .ok()?,
            )
            .ok()
        }
        "did_root" => serde_json::to_value(did_root_recovery_proof_transcript(record).ok()?).ok(),
        _ => None,
    }
}

#[derive(Clone)]
struct RecoveryTranscriptContext {
    request_id: RequestId,
    session_grant_id: SessionGrantId,
    session_grant_cnf_jkt: Challenge,
    account_id: AccountId,
    requesting_device_id: DeviceId,
    requesting_device_public_key_did: arkret_wire::DidKey,
    trust_domain: TrustDomainId,
    policy_id: PolicyId,
    policy_version: u64,
    recovery_session_id: RecoverySessionId,
    identity_model: RecoveryIdentityModel,
    model_generation_ref: u64,
    publication_authority_context_digest: Hash,
    challenge: Challenge,
    expires_at: chrono::DateTime<chrono::Utc>,
    created_at: chrono::DateTime<chrono::Utc>,
}

fn typed_recovery_transcript_context(
    record: &RecoverySessionServiceState,
) -> Result<RecoveryTranscriptContext, AppError> {
    Ok(RecoveryTranscriptContext {
        request_id: RequestId::new(record.request_id.clone())
            .map_err(|error| stored_recovery_type_error("request_id", error))?,
        session_grant_id: SessionGrantId::new(record.session_grant_id.clone())
            .map_err(|error| stored_recovery_type_error("session_grant_id", error))?,
        session_grant_cnf_jkt: Challenge::new(record.session_grant_cnf_jkt.clone())
            .map_err(|error| stored_recovery_type_error("session_grant_cnf_jkt", error))?,
        account_id: AccountId::new(record.principal_id.clone(), record.station_id.clone()),
        requesting_device_public_key_did: arkret_wire::DidKey::new(
            record.requesting_device_public_key_did.clone(),
        )
        .map_err(|error| stored_recovery_type_error("requesting_device_public_key_did", error))?,
        requesting_device_id: DeviceId::new(record.requesting_device_id.clone())
            .map_err(|error| stored_recovery_type_error("requesting_device_id", error))?,
        trust_domain: TrustDomainId::new(record.trust_domain.clone())
            .map_err(|error| stored_recovery_type_error("trust_domain", error))?,
        policy_id: PolicyId::new(record.policy_id.clone())
            .map_err(|error| stored_recovery_type_error("policy_id", error))?,
        policy_version: u64::from(record.policy_version),
        recovery_session_id: RecoverySessionId::new(record.recovery_session_id.clone())
            .map_err(|error| stored_recovery_type_error("recovery_session_id", error))?,
        identity_model: record.identity_model,
        model_generation_ref: record.current_device_generation_ref,
        publication_authority_context_digest: record.publication_authority_context_digest.clone(),
        challenge: Challenge::new(record.challenge.clone())
            .map_err(|error| stored_recovery_type_error("challenge", error))?,
        expires_at: record.expires_at,
        created_at: record.created_at,
    })
}

pub(super) fn typed_recovery_session_state(
    record: &RecoverySessionServiceState,
) -> Result<RecoverySessionState, AppError> {
    let transcript = typed_recovery_transcript_context(record)?;
    let state = RecoverySessionState {
        schema: SchemaId::RECOVERY_SESSION_V1.to_owned(),
        request_id: transcript.request_id,
        recovery_session_id: transcript.recovery_session_id,
        session_grant_id: transcript.session_grant_id,
        session_grant_cnf_jkt: transcript.session_grant_cnf_jkt,
        account_id: transcript.account_id,
        requesting_device_id: transcript.requesting_device_id,
        requesting_device_public_key_did: transcript.requesting_device_public_key_did,
        trust_domain: transcript.trust_domain,
        policy_id: transcript.policy_id,
        policy_version: transcript.policy_version,
        identity_model: transcript.identity_model,
        current_device_generation_ref: transcript.model_generation_ref,
        realm_stream_head: record.accepted_stream_head.clone(),
        publication_authority_context: record.publication_authority_context.clone(),
        publication_authority_context_digest: record.publication_authority_context_digest.clone(),
        challenge: Challenge::new(record.challenge.clone())
            .map_err(|error| stored_recovery_type_error("challenge", error))?,
        state: match record.state {
            SessionState::Pending => arkret_models_crypto::RecoverySessionState::Pending,
            SessionState::Verified => arkret_models_crypto::RecoverySessionState::Verified,
            SessionState::Completed => arkret_models_crypto::RecoverySessionState::Completed,
            SessionState::Rejected => arkret_models_crypto::RecoverySessionState::Rejected,
            SessionState::Expired => arkret_models_crypto::RecoverySessionState::Expired,
        },
        proof_summary: recovery_proof_summary(record),
        transaction_id: record
            .transaction_id
            .as_ref()
            .map(|value| TransactionId::new(value.clone()))
            .transpose()
            .map_err(|error| stored_recovery_type_error("transaction_id", error))?,
        rejection_reason_code: None,
        expires_at: record.expires_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    };
    state
        .validate_shape()
        .map_err(|error| stored_recovery_type_error("session state", error))?;
    Ok(state)
}

/// Snake_case wire name of a session state for diagnostics; the canonical SDK
/// [`SessionState`] enum has no `Display` impl.
fn session_state_label(state: SessionState) -> &'static str {
    match state {
        SessionState::Pending => "pending",
        SessionState::Verified => "verified",
        SessionState::Completed => "completed",
        SessionState::Rejected => "rejected",
        SessionState::Expired => "expired",
    }
}

async fn current_recovery_root_authority(
    state: &AppState,
    account_id: &AccountId,
) -> Result<(serde_json::Value, Vec<DidUrl>), AppError> {
    let authority = state
        .persistence()
        .principal_resolution_by_account_id(account_id)
        .await
        .map_err(|e| AppError::internal(format!("principal authority lookup failed: {e}")))?
        .ok_or_else(|| recovery_proof_authority_error("accepted principal resolution missing"))?;
    let pinned = state
        .dids()
        .resolve_current_webvh_state(&authority.projection.did)
        .await
        .map_err(|e| {
            recovery_proof_authority_error(format!("current root history unavailable: {e}"))
        })?;
    let methods = pinned
        .document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|method| {
            method
                .get("publicKeyMultibase")
                .and_then(Value::as_str)
                .is_some_and(|key| pinned.update_keys.iter().any(|root| root == key))
        })
        .filter_map(|method| method.get("id").and_then(Value::as_str))
        .map(|id| {
            DidUrl::new(id.to_owned()).map_err(|e| recovery_proof_authority_error(e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if methods.len() != 1 {
        return Err(recovery_proof_authority_error(
            "accepted root history must identify exactly one root method",
        ));
    }
    Ok((pinned.document, methods))
}

async fn device_quorum_methods_at_policy_basis(
    state: &AppState,
    active: &RecoveryPolicyState,
    policy: &RecoveryPolicy,
) -> Result<std::collections::BTreeMap<DeviceId, DidUrl>, AppError> {
    let mut methods = std::collections::BTreeMap::new();
    let Some(arkret_models_crypto::RecoveryMethod::DeviceQuorum { member_ids, .. }) =
        recovery_method(policy, RecoveryProofKind::DeviceQuorum)
    else {
        return Ok(methods);
    };
    let authority = state
        .persistence()
        .principal_resolution_by_account_id(&active.account_id)
        .await
        .map_err(|e| AppError::internal(format!("principal authority lookup failed: {e}")))?
        .ok_or_else(|| recovery_proof_authority_error("accepted principal resolution missing"))?;
    let basis = state
        .authority_commits()
        .committed_event_by_commit_id(&active.acceptance_basis)
        .await
        .map_err(|e| {
            recovery_proof_authority_error(format!("policy acceptance Commit unavailable: {e}"))
        })?
        .ok_or_else(|| recovery_proof_authority_error("policy acceptance Commit is missing"))?;
    if basis.commit.realm_id != authority.pcr_realm_id
        || basis.commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: basis.commit.realm_id.clone(),
            })
    {
        return Err(recovery_proof_authority_error(
            "policy acceptance basis is not a PCR RealmCommit",
        ));
    }
    let mut after_position = None;
    let mut events = Vec::new();
    let mut found_basis = false;
    loop {
        let page = state
            .authority_commits()
            .scan_stream(&arkret_wire::StreamScanRequestBody {
                realm_id: basis.commit.realm_id.clone(),
                stream_ref: basis.commit.stream_ref.clone(),
                direction: arkret_wire::StreamScanDirection::After(after_position),
                limit: 1000,
            })
            .await
            .map_err(|e| {
                recovery_proof_authority_error(format!(
                    "PCR history at policy basis unavailable: {e}"
                ))
            })?;
        if page.committed_events.is_empty() {
            return Err(recovery_proof_authority_error(
                "PCR history ended before the policy acceptance Commit",
            ));
        }
        for item in &page.committed_events {
            let commit = item.commit();
            if commit.stream_position > basis.commit.stream_position {
                break;
            }
            let event = item.reducer_input().ok_or_else(|| {
                recovery_proof_authority_error(
                    "PCR history withheld a device Event before policy acceptance",
                )
            })?;
            events.push(event.clone());
            if commit.commit_id == active.acceptance_basis {
                found_basis = true;
                break;
            }
        }
        if found_basis {
            break;
        }
        after_position = page
            .committed_events
            .last()
            .map(|item| item.commit().stream_position);
        if !page.truncated {
            return Err(recovery_proof_authority_error(
                "policy acceptance Commit not found in PCR history",
            ));
        }
    }
    for member in member_ids {
        let relevant = events
            .iter()
            .filter(|event| {
                event.actor_id.canonical_key().is_ok_and(|key| {
                    authorization_event_actor_matches_account(&key, &active.account_id)
                }) && event.realm_id == authority.pcr_realm_id
                    && event.payload.get("device_id").and_then(Value::as_str)
                        == Some(member.as_str())
            })
            .collect::<Vec<_>>();
        if !relevant
            .iter()
            .any(|event| event.kind == arkret_wire::EventKind::DeviceAuthorize)
            || relevant
                .iter()
                .any(|event| event.kind == arkret_wire::EventKind::DeviceRevoke)
        {
            return Err(recovery_proof_authority_error(format!(
                "quorum member {member} is not active at policy basis"
            )));
        }
        methods.insert(
            member.clone(),
            DidUrl::new(format!("{}#{member}", authority.projection.did))
                .map_err(|e| recovery_proof_authority_error(e.to_string()))?,
        );
    }
    Ok(methods)
}

fn materialize_recovery_authorization_rules(
    policy: &RecoveryPolicy,
    now: chrono::DateTime<chrono::Utc>,
    root_methods: &[DidUrl],
    device_methods: &std::collections::BTreeMap<DeviceId, DidUrl>,
) -> Result<Vec<AuthoritySetAuthorizationRule>, AppError> {
    let mut rules = Vec::new();
    for method in &policy.methods {
        let (role, methods, threshold) = match method {
            arkret_models_crypto::RecoveryMethod::DidRoot => (
                AuthoritySetIssuerRole::IdentityRecovery,
                root_methods.to_vec(),
                1,
            ),
            arkret_models_crypto::RecoveryMethod::RecoveryUnlock { keys } => (
                AuthoritySetIssuerRole::IdentityRecovery,
                keys.iter()
                    .filter(|key| {
                        key.not_before <= now
                            && now < key.expires_at
                            && key.revoked_at.is_none_or(|revoked_at| now < revoked_at)
                    })
                    .map(|key| key.verification_method.clone())
                    .collect(),
                1,
            ),
            arkret_models_crypto::RecoveryMethod::DeviceQuorum { k, member_ids } => (
                AuthoritySetIssuerRole::AcceptedDevice,
                member_ids
                    .iter()
                    .filter_map(|id| device_methods.get(id).cloned())
                    .collect(),
                *k,
            ),
            arkret_models_crypto::RecoveryMethod::TrustedRecoveryService { services } => (
                AuthoritySetIssuerRole::IdentityRecovery,
                services
                    .iter()
                    .map(|entry| entry.authorization_verification_method.clone())
                    .collect(),
                1,
            ),
        };
        let methods = methods.into_iter().collect::<BTreeSet<_>>();
        if methods.is_empty() || methods.len() < threshold as usize {
            return Err(recovery_proof_authority_error(format!(
                "recovery method {} has no executable issuer set",
                method.kind_str(),
            )));
        }
        rules.push(AuthoritySetAuthorizationRule {
            rule_id: method.kind_str().to_owned(),
            issuer_role: role,
            allowed_actions: vec![arkret_wire::event_kind_str::DEVICE_REANCHOR.to_owned()],
            issuers: methods
                .into_iter()
                .map(|verification_method| AuthoritySetAuthorizationIssuer {
                    verification_method,
                })
                .collect(),
            threshold,
        });
    }
    if rules.is_empty() {
        return Err(recovery_proof_authority_error(
            "revoked recovery policy cannot authorize publication",
        ));
    }
    Ok(rules)
}

async fn pcr_policy_recovery_publication_authority_context(
    state: &AppState,
    active: &RecoveryPolicyState,
    realm_id: &RealmId,
) -> Result<PublicationAuthorityContext, AppError> {
    let policy: RecoveryPolicy =
        serde_json::from_value(active.raw_payload.clone()).map_err(|error| {
            AppError::internal(format!("stored recovery policy is invalid: {error}"))
        })?;
    policy.validate_shape().map_err(|error| {
        AppError::conflict(format!(
            "stored recovery policy cannot define publication authority: {error}"
        ))
        .with_internal_reason("recovery_publication_authority_invalid")
    })?;
    let device_methods = device_quorum_methods_at_policy_basis(state, active, &policy).await?;
    let root_methods = if recovery_method(&policy, RecoveryProofKind::DidRoot).is_some() {
        current_recovery_root_authority(state, &active.account_id)
            .await?
            .1
    } else {
        Vec::new()
    };
    let derived_rules = materialize_recovery_authorization_rules(
        &policy,
        chrono::Utc::now(),
        &root_methods,
        &device_methods,
    )?;

    let authority_set_policy = AuthoritySetPolicy {
        schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
        authority_set_id: AuthoritySetId::RECOVERY_IDENTITY_REANCHOR_V1.to_owned(),
        policy_kind: AuthoritySetPolicyKind::PrincipalControl,
        scope_ref: arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        source_commit_id: active.acceptance_basis.clone(),
        authorization_rules: derived_rules,
    };
    let context = PublicationAuthorityContext {
        authority_commit_id: active.acceptance_basis.clone(),
        scope_ref: authority_set_policy.scope_ref.clone(),
        authority_set_policy,
        allowed_actions: vec![arkret_wire::event_kind_str::DEVICE_REANCHOR.to_owned()],
    };
    context.validate_shape().map_err(|error| {
        AppError::conflict(format!(
            "recovery publication authority context is invalid: {error}"
        ))
        .with_internal_reason("recovery_publication_authority_invalid")
    })?;
    Ok(context)
}

/// Revalidate frozen authority against accepted expiry and explicit revocations.
fn selected_recovery_method_active(
    policy: &RecoveryPolicy,
    proof: &arkret_models_crypto::RecoverySessionProof,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    use arkret_models_crypto::{RecoveryMethod, RecoverySessionProof};
    policy.methods.iter().any(|method| match (method, proof) {
        (RecoveryMethod::DidRoot, RecoverySessionProof::DidRoot(_)) => true,
        (RecoveryMethod::RecoveryUnlock { keys }, RecoverySessionProof::RecoveryUnlock(proof)) => {
            keys.iter().any(|key| {
                key.verification_method == proof.verification_method
                    && key.not_before <= now
                    && now < key.expires_at
                    && key.revoked_at.is_none_or(|revoked_at| now < revoked_at)
            })
        }
        (
            RecoveryMethod::DeviceQuorum { k, member_ids },
            RecoverySessionProof::DeviceQuorum(proof),
        ) => {
            *k <= proof
                .signatures
                .iter()
                .map(|signature| &signature.device_id)
                .collect::<BTreeSet<_>>()
                .len() as u32
                && proof
                    .signatures
                    .iter()
                    .all(|signature| member_ids.contains(&signature.device_id))
        }
        (
            RecoveryMethod::TrustedRecoveryService { services },
            RecoverySessionProof::TrustedRecoveryService(proof),
        ) => services.iter().any(|entry| {
            entry.service_id == proof.service_id
                && entry.audience == proof.audience
                && entry.authorization_verification_method == proof.verification_method
        }),
        _ => false,
    })
}

pub(crate) async fn validate_frozen_session_policy(
    state: &AppState,
    record: &RecoverySessionServiceState,
    proof_payload: Option<&Value>,
) -> Result<(), AppError> {
    let frozen: RecoveryPolicy =
        serde_json::from_value(record.policy_payload.clone()).map_err(|error| {
            recovery_proof_authority_error(format!("bound policy invalid: {error}"))
        })?;
    let history = state
        .recovery_policies()
        .policy_history(&AccountId::new(
            record.principal_id.clone(),
            record.station_id.clone(),
        ))
        .await
        .map_err(recovery_service_error)?;
    let updates = history
        .into_iter()
        .map(|entry| serde_json::from_value(entry.raw_payload))
        .collect::<Result<Vec<RecoveryPolicy>, _>>()
        .map_err(|error| {
            recovery_proof_authority_error(format!("accepted policy invalid: {error}"))
        })?;
    let proof = proof_payload
        .or(record.proof_payload.as_ref())
        .map(|value| {
            serde_json::from_value::<arkret_models_crypto::RecoverySessionProofSubmitRequestBody>(
                value.clone(),
            )
        })
        .transpose()
        .map_err(|error| recovery_proof_authority_error(format!("bound proof invalid: {error}")))?;
    if updates.first() != Some(&frozen) {
        return Err(recovery_proof_authority_error(
            "frozen recovery policy is not the accepted policy at its version",
        ));
    }
    let now = chrono::Utc::now();
    for policy in &updates {
        policy.validate_shape().map_err(|error| {
            recovery_proof_authority_error(format!("accepted recovery policy is invalid: {error}"))
        })?;
        if policy.revokes_recovery()
            || policy.not_before.is_some_and(|not_before| now < not_before)
            || policy
                .expires_at
                .is_some_and(|expires_at| now >= expires_at)
            || proof
                .as_ref()
                .is_some_and(|value| !selected_recovery_method_active(policy, &value.proof, now))
        {
            return Err(recovery_proof_authority_error(
                "bound recovery method was revoked, expired, or no longer active",
            ));
        }
    }
    Ok(())
}

pub(super) async fn load_owned_recovery_session(
    aa: &AuthArgs,
    state: &AppState,
    req: &mut Request,
    recovery_session_id: &str,
) -> Result<RecoverySessionServiceState, AppError> {
    let session = aa.authenticated_session(state, req).await?;
    let (grant_id, grant_jkt, candidate_device_id) = recovery_grant_coordinates(&session)?;
    let principal = session.actor;
    let record = state
        .recovery_sessions()
        .session(recovery_session_id)
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| {
            AppError::not_found(format!(
                "recovery session `{recovery_session_id}` not found"
            ))
        })?;
    if record.principal_id.as_str() != principal
        || record.station_id.as_str() != session.audience
        || record.requesting_device_id != candidate_device_id
        || record.session_grant_id != grant_id
        || record.session_grant_cnf_jkt != grant_jkt
    {
        return Err(crate::app_error!(
            CapabilityDenied,
            "recovery session belongs to a different principal",
        )
        .with_reason_code("recovery_principal_isolation"));
    }
    if matches!(record.state, SessionState::Pending | SessionState::Verified) {
        validate_frozen_session_policy(state, &record, None).await?;
    }
    Ok(record)
}

fn recovery_grant_coordinates(
    session: &SessionRecord,
) -> Result<(String, String, String), AppError> {
    let grant = session.session_grant.as_ref().ok_or_else(|| {
        AppError::unauthenticated("recovery operation requires a recovery_session SessionGrant")
    })?;
    if grant.credential_class
        != arkret_models_identity::SessionGrantCredentialClass::RecoverySession
        || grant.device_binding.is_some()
    {
        return Err(crate::app_error!(
            CapabilityDenied,
            "recovery operation requires a restricted recovery_session grant",
        ));
    }
    let arkret_models_identity::SessionGrantHolderBinding::RecoveryCandidateDevice { device_id } =
        &grant.holder_binding
    else {
        return Err(AppError::unauthenticated(
            "recovery session grant has the wrong holder binding",
        ));
    };
    if device_id.as_str() != session.require_human_device_id() {
        return Err(AppError::unauthenticated(
            "recovery candidate device does not match the authenticated session",
        ));
    }
    Ok((
        grant.grant_id.to_string(),
        grant.cnf_jkt.clone(),
        device_id.to_string(),
    ))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.recovery_session.command.create",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.recovery_session.command.create.v1")
)]
pub(super) async fn recovery_session_create(
    aa: AuthArgs,
    body: JsonBody<RecoverySessionCreateRequestBody>,
    depot: &mut Depot,
    res: &mut Response,
    req: &mut Request,
) -> JsonResult<RecoverySessionState> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let (session_grant_id, session_grant_cnf_jkt, candidate_device_id) =
        recovery_grant_coordinates(&session)?;
    let principal = session.actor.clone();
    let payload = body.into_inner();
    verify_recovery_device_possession(&payload, &session_grant_id, &session_grant_cnf_jkt)?;
    let create_intent_digest = Hash::new(arkret_canonical::canonical_sha256(&payload).map_err(
        |error| AppError::internal(format!("recovery create canonicalization failed: {error}")),
    )?)
    .map_err(|error| AppError::internal(format!("recovery create digest failed: {error}")))?;
    if payload.requesting_device_id.as_str() != candidate_device_id {
        return Err(crate::app_error!(
            CapabilityDenied,
            "requesting_device_id does not match the recovery grant holder",
        )
        .with_reason_code("recovery_evidence_unbound"));
    }
    if let Some(existing) = state
        .recovery_sessions()
        .session_for_request(&session_grant_id, payload.request_id.as_str())
        .await
        .map_err(recovery_session_store_error)?
    {
        if existing.create_intent_digest == create_intent_digest.as_str() {
            let existing = expire_if_elapsed(state, existing).await?;
            if matches!(
                existing.state,
                SessionState::Pending | SessionState::Verified
            ) {
                validate_frozen_session_policy(state, &existing, None).await?;
            }
            return json_ok(typed_recovery_session_state(&existing)?);
        }
        return Err(AppError::conflict(
            "recovery request_id was already used with a different create intent",
        )
        .with_wire_code("duplicate_conflict"));
    }
    if state
        .recovery_sessions()
        .session_for_grant(&session_grant_id)
        .await
        .map_err(recovery_session_store_error)?
        .is_some()
    {
        return Err(AppError::conflict(
            "recovery SessionGrant is already bound to another recovery session",
        )
        .with_wire_code("duplicate_conflict"));
    }

    let account_id = payload.account_id;
    if account_id.principal_id.as_str() != principal {
        return Err(crate::app_error!(
            CapabilityDenied,
            "account_id.principal_id does not match the authenticated principal",
        )
        .with_reason_code("recovery_principal_isolation"));
    }
    if account_id.station_id.as_str() != state.service_id() {
        return Err(
            crate::app_error!(FailedPrecondition, "account_id does not bind this Station",)
                .with_internal_reason("account_id_mismatch"),
        );
    }
    let authority_record = state
        .persistence()
        .principal_resolution_by_account_id(&account_id)
        .await
        .map_err(|error| AppError::internal(format!("principal authority lookup failed: {error}")))?
        .ok_or_else(|| {
            crate::app_error!(
                FailedPrecondition,
                "principal authority is not accepted by this Station",
            )
            .with_internal_reason("account_id_mismatch")
        })?;
    let requesting_device_id = payload.requesting_device_id.as_str().to_owned();
    if !requesting_device_id.starts_with("ak:device:") {
        return Err(AppError::param_invalid(format!(
            "requesting_device_id `{requesting_device_id}` must start with ak:device:",
        )));
    }
    let trust_domain = payload.trust_domain.as_str().to_owned();
    if !trust_domain.starts_with("ak:trust_domain:") {
        return Err(AppError::param_invalid(format!(
            "trust_domain `{trust_domain}` must start with ak:trust_domain:",
        )));
    }
    // A session can only be opened against an accepted recovery policy — and the
    // requested trust_domain MUST match it (no domain confusion).
    let active = state
        .recovery_policies()
        .active_policy(&account_id)
        .await
        .map_err(recovery_service_error)?
        .ok_or_else(|| {
            AppError::conflict(format!(
                "no accepted recovery policy for principal `{principal}`"
            ))
            .with_wire_code("recovery_policy_mismatch")
        })?;
    if active.trust_domain != trust_domain {
        return Err(AppError::conflict(format!(
            "trust_domain `{trust_domain}` does not match active policy `{}`",
            active.trust_domain
        ))
        .with_internal_reason("recovery_policy_trust_domain_mismatch"));
    }
    if active
        .raw_payload
        .get("methods")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        // An explicit-revocation policy (methods == []) cannot back a
        // recovery session — there is no proof the requester_id could ever satisfy.
        return Err(AppError::conflict(format!(
            "active recovery policy `{}` permits no proof kinds (recovery disabled)",
            active.policy_id
        ))
        .with_internal_reason("recovery_policy_revoked"));
    }

    let active_policy: RecoveryPolicy = serde_json::from_value(active.raw_payload.clone())
        .map_err(|e| recovery_proof_authority_error(format!("accepted policy invalid: {e}")))?;
    active_policy
        .validate_shape()
        .map_err(|e| recovery_proof_authority_error(e.to_string()))?;
    let now = chrono::Utc::now();
    if active_policy.not_before.is_some_and(|time| now < time)
        || active_policy.expires_at.is_some_and(|time| now >= time)
    {
        return Err(recovery_proof_authority_error(
            "accepted recovery policy is outside its active interval",
        ));
    }
    // Optional client CAS hint: if `expected_recovery_policy_ref` is present it
    // MUST match the policy the server is about to snapshot, else the client is
    // racing a policy rotation → recovery_policy_mismatch.
    if let Some(expected) = payload.expected_recovery_policy_ref.as_ref()
        && (expected.policy_id.as_str() != active.policy_id
            || expected.policy_version != active.version as u64)
    {
        return Err(AppError::conflict(format!(
            "expected_recovery_policy_ref does not match active policy `{}` v{}",
            active.policy_id, active.version
        ))
        .with_wire_code("recovery_policy_mismatch"));
    }

    let device_generation =
        crate::routing::identity::device_generation::current_device_generation(state, &principal)
            .await
            .map_err(recovery_store_error)?;
    let realm_id = authority_record.pcr_realm_id;
    let (identity_model, current_device_generation_ref, accepted_stream_head) =
        if let Some(generation) = device_generation {
            let accepted_stream_head =
            crate::routing::identity::device_generation::accepted_device_generation_commit_head(
                state, &principal, &realm_id,
            )
            .await
            .map_err(recovery_store_error)?
            .ok_or_else(|| {
                AppError::conflict("recovery requires a non-empty accepted RealmCommit stream")
                    .with_internal_reason("device_reanchor_frontier_mismatch")
            })?;
            (
                RecoveryIdentityModel::PcrPolicy,
                generation.current_ref,
                accepted_stream_head,
            )
        } else {
            return Err(
                AppError::conflict("recovery requires an accepted device generation")
                    .with_internal_reason("device_generation_missing"),
            );
        };

    let publication_authority_context =
        pcr_policy_recovery_publication_authority_context(state, &active, &realm_id).await?;
    let publication_authority_context_digest = Hash::new(
        arkret_canonical::canonical_sha256(&publication_authority_context).map_err(|error| {
            AppError::internal(format!(
                "recovery publication authority context digest failed: {error}"
            ))
        })?,
    )
    .map_err(|error| AppError::internal(format!("recovery authority digest: {error}")))?;
    let current_authority = state
        .authority_commits()
        .current_authority(&realm_id)
        .await
        .map_err(|error| AppError::internal(format!("PCR authority lookup failed: {error}")))?
        .ok_or_else(|| {
            AppError::conflict("PCR Realm has no current governance authority")
                .with_internal_reason("device_reanchor_frontier_mismatch")
        })?;
    let authority_context = coland_storage::RecoveryAuthorityContext {
        realm_id: realm_id.clone(),
        authority_generation: current_authority.generation,
        authority_ref: current_authority.authority_ref,
        realm_stream_head: accepted_stream_head.clone(),
    };
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let record = RecoverySessionServiceState {
        request_id: payload.request_id.to_string(),
        create_intent_digest: create_intent_digest.to_string(),
        recovery_session_id: crate::ids::generate("recovery_session"),
        session_grant_id,
        session_grant_cnf_jkt,
        principal_id: account_id.principal_id.clone(),
        station_id: account_id.station_id.clone(),
        requesting_device_id,
        requesting_device_public_key_did: payload.requesting_device_public_key_did.to_string(),
        trust_domain,
        policy_id: active.policy_id.clone(),
        policy_version: active.version,
        identity_model,
        current_device_generation_ref,
        accepted_stream_head,
        policy_payload: active.raw_payload.clone(),
        authority_context,
        publication_authority_context,
        publication_authority_context_digest,
        challenge: generate_recovery_challenge(),
        state: SessionState::Pending,
        proof_payload: None,
        transaction_id: None,
        created_at: now,
        updated_at: now,
        expires_at: (now + chrono::Duration::seconds(RECOVERY_SESSION_TTL_SECS))
            .min(session.expires_at)
            .min(active_policy.expires_at.unwrap_or(session.expires_at)),
    };
    if let Err(error) = state
        .recovery_sessions()
        .create_session(record.clone())
        .await
    {
        if error.conflict_code() == Some(coland_storage::ConflictCode::RecoverySessionAlreadyExists)
        {
            if let Some(existing) = state
                .recovery_sessions()
                .session_for_request(&record.session_grant_id, record.request_id.as_str())
                .await
                .map_err(recovery_session_store_error)?
            {
                if existing.create_intent_digest == record.create_intent_digest {
                    return json_ok(typed_recovery_session_state(&existing)?);
                }
                return Err(AppError::conflict(
                    "recovery request_id was concurrently used with a different create intent",
                )
                .with_wire_code("duplicate_conflict"));
            }
            if state
                .recovery_sessions()
                .session_for_grant(&record.session_grant_id)
                .await
                .map_err(recovery_session_store_error)?
                .is_some()
            {
                return Err(AppError::conflict(
                    "recovery SessionGrant was concurrently bound to another recovery session",
                )
                .with_wire_code("duplicate_conflict"));
            }
        }
        return Err(recovery_session_store_error(error));
    }

    append_audit_log(
        state,
        Some(&session.actor),
        arkret_wire::ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE_V1,
        json!({
            "recovery_session_id": record.recovery_session_id.clone(),
            "account_id": {
                "principal_id": record.principal_id.clone(),
                "station_id": record.station_id.clone(),
            },
            "policy_id": record.policy_id.clone(),
            "trust_domain": record.trust_domain.clone(),
        }),
        "created",
    )
    .await;

    res.status_code(StatusCode::CREATED);
    json_ok(typed_recovery_session_state(&record)?)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.recovery_session.resource.get",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.recovery_session.resource.get.v1")
)]
pub(super) async fn recovery_session_get(
    aa: AuthArgs,
    recovery_session_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RecoverySessionState> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let mut record =
        load_owned_recovery_session(&aa, state, req, &recovery_session_id.into_inner()).await?;
    record = expire_if_elapsed(state, record).await?;
    json_ok(typed_recovery_session_state(&record)?)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.root.identity.recovery_session.command.submit_proof",
    tags("identity")
)]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.root.identity.recovery_session.command.submit_proof.v1")
)]
pub(super) async fn recovery_session_proof_submit(
    aa: AuthArgs,
    recovery_session_id: PathParam<String>,
    body: JsonBody<RecoverySessionProofSubmitRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<RecoverySessionProofSubmitResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session_id = recovery_session_id.into_inner();
    let record = load_owned_recovery_session(&aa, state, req, &session_id).await?;
    let record = expire_if_elapsed(state, record).await?;
    if record.state != SessionState::Pending {
        return Err(AppError::conflict(format!(
            "recovery session is `{}`, proofs accepted only while `pending`",
            session_state_label(record.state)
        ))
        .with_wire_code("recovery_session_not_pending"));
    }

    let payload = body.into_inner();
    let payload_value = serde_json::to_value(&payload)
        .map_err(|error| AppError::internal(format!("recovery proof submit serialize: {error}")))?;
    let proof = payload_value
        .get("proof")
        .ok_or_else(|| AppError::param_invalid("proof object is required"))?
        .as_object()
        .ok_or_else(|| AppError::param_invalid("proof object is required"))?;
    let proof_kind = proof
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid("proof.kind is required"))?;
    if !ALLOWED_PROOF_KINDS.contains(&proof_kind) {
        return Err(AppError::param_invalid(
            format!("proof.kind `{proof_kind}` not in spec enum",),
        )
        .with_reason_code("recovery_proof_kind_unknown"));
    }
    // The proof kind MUST be one the bound policy snapshot permits.
    let policy_allows = record
        .policy_payload
        .get("methods")
        .and_then(Value::as_array)
        .map(|kinds| {
            kinds
                .iter()
                .any(|k| k.get("kind").and_then(Value::as_str) == Some(proof_kind))
        })
        .unwrap_or(false);
    if !policy_allows {
        return Err(AppError::conflict(format!(
            "proof.kind `{proof_kind}` is not permitted by the bound recovery policy",
        ))
        .with_internal_reason("recovery_proof_kind_not_allowed"));
    }
    let bound_policy: RecoveryPolicy = serde_json::from_value(record.policy_payload.clone())
        .map_err(|e| recovery_proof_authority_error(format!("bound policy invalid: {e}")))?;
    if bound_policy.cooldown_seconds.is_some_and(|seconds| {
        chrono::Utc::now()
            .signed_duration_since(record.created_at)
            .num_seconds()
            < i64::try_from(seconds).unwrap_or(i64::MAX)
    }) {
        return Err(recovery_proof_authority_error(
            "policy recovery cooldown has not elapsed",
        ));
    }
    // Anti-replay: the proof MUST echo the server-issued session challenge.
    let echoed = proof
        .get("challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::param_invalid("proof.challenge is required"))?;
    if !constant_time_str_eq(echoed, &record.challenge) {
        return Err(crate::app_error!(
            SignatureInvalid,
            "proof.challenge does not match the session challenge",
        )
        .with_reason_code("recovery_session_challenge_mismatch"));
    }

    validate_frozen_session_policy(state, &record, Some(&payload_value)).await?;
    // Each enabled method is verified independently against its frozen policy.
    match proof_kind {
        "did_root" => {
            verify_did_root_proof(state, &record, proof).await?;
        }
        "recovery_unlock" => {
            verify_recovery_unlock_proof(state, &record, proof).await?;
        }
        "trusted_recovery_service" => {
            verify_trusted_recovery_service_proof(state, &record, proof).await?;
        }
        "device_quorum" => {
            verify_device_quorum_recovery_proof(state, &record, proof).await?;
        }
        other => {
            return Err(AppError::unsupported_feature(format!(
                "proof.kind `{other}` verification not yet implemented (C-P3)"
            ))
            .with_internal_reason("recovery_proof_kind_unimplemented"));
        }
    }

    // Proof verified — advance `pending -> verified` and record the proof. The
    // server only reaches this point after a real cryptographic check.
    let now = chrono::Utc::now();
    let updated = RecoverySessionServiceState {
        state: SessionState::Verified,
        proof_payload: Some(payload_value.clone()),
        updated_at: now,
        ..record
    };
    let manifest = crate::routing::identity::key_backup::recovery_unlock_manifest(
        state,
        &AccountId::new(updated.principal_id.clone(), updated.station_id.clone()),
    )
    .await?;
    state
        .recovery_sessions()
        .save_verified_with_unlock_manifest(updated.clone(), manifest)
        .await
        .map_err(recovery_session_store_error)?;

    let proof_summary = recovery_proof_summary(&updated);
    append_audit_log(
        state,
        Some(updated.principal_id.as_str()),
        arkret_wire::ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF_V1,
        json!({
            "recovery_session_id": updated.recovery_session_id.clone(),
            "principal_id": updated.principal_id.clone(),
            "policy_id": updated.policy_id.clone(),
            "trust_domain": updated.trust_domain.clone(),
            "proof_kind": proof_kind,
            "verification_method": proof
                .get("verification_method")
                .cloned()
                .unwrap_or(Value::Null),
            "service_id": proof
                .get("service_id")
                .cloned()
                .unwrap_or(Value::Null),
            "proof_summary": proof_summary,
        }),
        "verified",
    )
    .await;

    // A 2xx reply already means the proof verified and the session entered
    // `verified`, so the outcome echoes neither `state` nor `verification`.
    json_ok(RecoverySessionProofSubmitResponseBody {
        recovery_session_id: RecoverySessionId::new(updated.recovery_session_id.clone())
            .map_err(|error| stored_recovery_type_error("recovery_session_id", error))?,
        proof_summary: recovery_proof_summary(&updated),
    })
}

/// C-P3 — verify a `did_root` recovery proof.
///
/// The proof MUST carry an Ed25519 signature by the principal's signing key
/// over the canonical recovery-proof transcript, which binds every
/// session-defining field: `(principal_id, requesting_device_id, trust_domain,
/// policy_id, policy_version, recovery_session_id, device generation, challenge,
/// created_at, expires_at)`.
/// Because the transcript is reconstructed server-side from the stored session,
/// any proof signed over a different binding (stale policy, replayed across
/// principal/domain, different session) fails verification — this gives the
/// `recovery_evidence_unbound` guarantee for free.
async fn verify_device_quorum_recovery_proof(
    state: &AppState,
    record: &RecoverySessionServiceState,
    proof: &Map<String, Value>,
) -> Result<(), AppError> {
    let proof: arkret_models_crypto::DeviceQuorumProofBodyWithSignatures =
        serde_json::from_value(Value::Object(proof.clone()))
            .map_err(|e| recovery_signature_error(format!("invalid device quorum proof: {e}")))?;
    let policy: RecoveryPolicy = serde_json::from_value(record.policy_payload.clone())
        .map_err(|e| recovery_proof_authority_error(format!("bound policy invalid: {e}")))?;
    let Some(arkret_models_crypto::RecoveryMethod::DeviceQuorum { k, member_ids }) =
        recovery_method(&policy, RecoveryProofKind::DeviceQuorum)
    else {
        return Err(recovery_proof_authority_error(
            "device quorum method is not enabled",
        ));
    };
    let rule = record
        .publication_authority_context
        .authority_set_policy
        .authorization_rules
        .iter()
        .find(|rule| rule.rule_id == "device_quorum")
        .ok_or_else(|| recovery_proof_authority_error("frozen quorum authority missing"))?;
    if proof.threshold != *k || rule.threshold != *k {
        return Err(recovery_proof_authority_error(
            "quorum threshold does not equal the accepted method",
        ));
    }
    let body = device_quorum_transcript_body(&proof);
    let transcript =
        generic_recovery_proof_transcript(record, RecoveryTranscriptProofBody::DeviceQuorum(body))?;
    let bytes = arkret_canonical::canonical_json_bytes(&transcript)
        .map_err(|e| AppError::internal(e.to_string()))?;
    let account = AccountId::new(record.principal_id.clone(), record.station_id.clone());
    let mut seen = BTreeSet::new();
    for signature in &proof.signatures {
        if !seen.insert(signature.device_id.clone())
            || !member_ids.contains(&signature.device_id)
            || signature.signature_algorithm
                != arkret_models_crypto::RecoverySignatureAlgorithm::Ed25519
            || !rule
                .issuers
                .iter()
                .any(|issuer| issuer.verification_method == signature.verification_method)
        {
            return Err(recovery_proof_authority_error(
                "quorum contains a duplicate, unlisted or differently bound signer",
            ));
        }
        let key = crate::jws_verify::resolve_principal_authorized_device_key_with_account_authority_async(
            signature.verification_method.as_str(), &account, &signature.device_id, state,
        ).await.map_err(|e| recovery_proof_authority_error(e.to_string()))?;
        let raw = URL_SAFE_NO_PAD
            .decode(signature.signature.as_str())
            .map_err(|_| recovery_signature_error("quorum signature is not canonical base64url"))?;
        let decoded = Signature::from_slice(&raw)
            .map_err(|_| recovery_signature_error("quorum signature must contain 64 bytes"))?;
        key.verify(&bytes, &decoded)
            .map_err(|_| recovery_signature_error("quorum signature is invalid"))?;
    }
    if seen.len() < *k as usize {
        return Err(recovery_proof_authority_error(
            "quorum has too few distinct valid members",
        ));
    }
    Ok(())
}

pub(super) async fn verify_did_root_proof(
    state: &AppState,
    record: &RecoverySessionServiceState,
    proof: &Map<String, Value>,
) -> Result<(), AppError> {
    if record.station_id.as_str() != state.service_id() {
        return Err(recovery_signature_error(
            "recovery session principal authority pair does not bind this Station",
        ));
    }
    let verification_method = required_proof_string(proof, "verification_method")?;
    let account_id = AccountId::new(record.principal_id.clone(), record.station_id.clone());
    let (document, roots) = current_recovery_root_authority(state, &account_id).await?;
    if !roots
        .iter()
        .any(|root| root.as_str() == verification_method)
    {
        return Err(recovery_signature_error(
            "did_root proof requires the current DID history root, not a device key",
        ));
    }
    let document = crate::jws_verify::decode_pinned_did_document(&document)
        .map_err(recovery_signature_error)?;
    let key =
        arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, verification_method)
            .map_err(|e| recovery_signature_error(e.to_string()))?;
    let transcript = did_root_recovery_proof_transcript(record)?;
    let transcript_bytes =
        arkret_canonical::canonical_json_bytes(&transcript).map_err(|error| {
            AppError::internal(format!("recovery proof transcript failed: {error}"))
        })?;
    let signature_b64 = required_proof_string(proof, "signature")?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| recovery_signature_error("proof.signature is not base64/base64url"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| recovery_signature_error("proof.signature must be 64 Ed25519 bytes"))?;
    key.verify(&transcript_bytes, &signature).map_err(|_| {
        crate::metrics::record_digest_mismatch("recovery_proof_digest");
        recovery_signature_error("did-root recovery proof signature verification failed")
    })
}

pub(super) async fn verify_trusted_recovery_service_proof(
    state: &AppState,
    record: &RecoverySessionServiceState,
    proof: &Map<String, Value>,
) -> Result<(), AppError> {
    let signature_algorithm = required_proof_string(proof, "signature_algorithm")?;
    if signature_algorithm != "Ed25519" {
        return Err(AppError::param_invalid(format!(
            "proof.signature_algorithm `{signature_algorithm}` must be `Ed25519`",
        )));
    }
    let service_id = required_proof_string(proof, "service_id")?;
    let audience = required_proof_string(proof, "audience")?;
    let verification_method = required_proof_string(proof, "verification_method")?;
    let _service_id =
        arkret_identifiers::DidCoreId::new(service_id.to_owned()).map_err(|error| {
            recovery_proof_authority_error(format!("proof.service_id is invalid: {error}"))
        })?;
    let policy: RecoveryPolicy = serde_json::from_value(record.policy_payload.clone())
        .map_err(|e| recovery_proof_authority_error(format!("bound policy invalid: {e}")))?;
    let Some(arkret_models_crypto::RecoveryMethod::TrustedRecoveryService { services }) =
        recovery_method(&policy, RecoveryProofKind::TrustedRecoveryService)
    else {
        return Err(recovery_proof_authority_error(
            "trusted service method is not enabled",
        ));
    };
    services
        .iter()
        .find(|entry| {
            entry.service_id.as_str() == service_id
                && entry.audience.as_str() == audience
                && entry.authorization_verification_method.as_str() == verification_method
        })
        .ok_or_else(|| {
            recovery_proof_authority_error(
                "service, audience and signing method do not exactly match the accepted method",
            )
        })?;
    crate::jws_verify::validate_verification_method_controller(service_id, verification_method)
        .map_err(|error| {
            recovery_proof_authority_error(format!(
                "proof.verification_method authority invalid: {error}"
            ))
        })?;
    let service_key = crate::jws_verify::resolve_ed25519_pubkey_async(state, verification_method)
        .await
        .map_err(|error| {
            recovery_proof_authority_error(format!("trusted recovery service key invalid: {error}"))
        })?;
    let proof_body = trusted_recovery_service_proof_body(proof)?;
    let transcript = generic_recovery_proof_transcript(
        record,
        RecoveryTranscriptProofBody::TrustedRecoveryService(proof_body),
    )?;
    let transcript_bytes =
        arkret_canonical::canonical_json_bytes(&transcript).map_err(|error| {
            AppError::internal(format!("recovery proof transcript failed: {error}"))
        })?;
    let signature_b64 = required_proof_string(proof, "signature")?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| recovery_signature_error("proof.signature is not base64/base64url"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| recovery_signature_error("proof.signature must be 64 Ed25519 bytes"))?;
    service_key
        .verify(&transcript_bytes, &signature)
        .map_err(|_| {
            crate::metrics::record_digest_mismatch("recovery_proof_digest");
            recovery_signature_error("trusted recovery service proof signature verification failed")
        })
}

/// §15 step 2 — verify a `recovery_unlock` recovery proof.
///
/// The 24-word Recovery Key (§3.3) unlock factor. Trust root is the principal's
/// own published `recovery_policy.methods[kind=recovery_unlock].keys[]` (not the DID document):
///
/// (a) `verification_method` MUST select exactly one
///     `methods[kind=recovery_unlock].keys[]` entry that was authoritative at
///     the session `created_at` (not_before/expires_at window, not revoked);
/// (b) `signature` (under the entry's `signature_algorithm`, Ed25519) MUST verify over the
///     generic recovery transcript whose proof_body is this proof object with
///     `signature` removed, using the public key decoded from the entry's
///     `public_key_multibase`.
pub(super) async fn verify_recovery_unlock_proof(
    _state: &AppState,
    record: &RecoverySessionServiceState,
    proof: &Map<String, Value>,
) -> Result<(), AppError> {
    let signature_algorithm = required_proof_string(proof, "signature_algorithm")?;
    if signature_algorithm != "Ed25519" {
        return Err(AppError::param_invalid(format!(
            "proof.signature_algorithm `{signature_algorithm}` must be `Ed25519` for recovery_unlock",
        )));
    }
    let verification_method = required_proof_string(proof, "verification_method")?;

    // (a) Resolve the recovery key entry from the bound recovery policy.
    let entry = resolve_recovery_key_entry(
        &record.policy_payload,
        verification_method,
        record.created_at,
    )?;
    let entry_method = entry
        .get("verification_method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if entry_method != verification_method {
        return Err(recovery_evidence_unbound_error(
            "recovery_unlock verification_method does not match the resolved recovery key entry",
        ));
    }
    let entry_signature_algorithm = entry
        .get("signature_algorithm")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if entry_signature_algorithm != signature_algorithm {
        return Err(recovery_evidence_unbound_error(
            "recovery_unlock proof.signature_algorithm does not match the recovery key entry signature_algorithm",
        ));
    }
    let recovery_key = decode_recovery_key_public_key(&entry)?;

    // Build the SDK-owned signature-independent binding transcript once. The
    // exact frozen policy method and every session coordinate are covered by
    // this one possession signature; there is no second public commitment.
    let proof_body = recovery_unlock_proof_body(proof)?;
    let transcript = generic_recovery_proof_transcript(
        record,
        RecoveryTranscriptProofBody::RecoveryUnlock(proof_body),
    )?;
    let transcript_bytes =
        arkret_canonical::canonical_json_bytes(&transcript).map_err(|error| {
            AppError::internal(format!("recovery_unlock transcript failed: {error}"))
        })?;

    // Signature possession proof.
    let signature_b64 = required_proof_string(proof, "signature")?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| recovery_signature_error("proof.signature is not base64/base64url"))?;
    let signature = Signature::from_slice(&raw)
        .map_err(|_| recovery_signature_error("proof.signature must be 64 Ed25519 bytes"))?;
    recovery_key
        .verify(&transcript_bytes, &signature)
        .map_err(|_| {
            crate::metrics::record_digest_mismatch("recovery_proof_digest");
            recovery_signature_error("recovery_unlock proof signature verification failed")
        })
}

fn recovery_unlock_proof_body(
    proof: &Map<String, Value>,
) -> Result<arkret_models_crypto::RecoveryUnlockProofBody, AppError> {
    let proof =
        serde_json::from_value::<arkret_models_crypto::RecoveryUnlockProofBodyWithSignature>(
            Value::Object(proof.clone()),
        )
        .map_err(|error| {
            AppError::param_invalid(format!("invalid recovery_unlock proof: {error}"))
        })?;
    Ok(arkret_models_crypto::RecoveryUnlockProofBody {
        kind: proof.kind,
        challenge: proof.challenge,
        verification_method: proof.verification_method,
        signature_algorithm: proof.signature_algorithm,
    })
}

/// Resolve a non-revoked, in-window `methods[kind=recovery_unlock].keys[]`
/// entry whose `verification_method` equals the signed proof method, evaluated
/// at `evaluated_at` (the recovery session `created_at`).
pub(super) fn resolve_recovery_key_entry(
    policy_payload: &Value,
    verification_method: &str,
    evaluated_at: chrono::DateTime<chrono::Utc>,
) -> Result<Map<String, Value>, AppError> {
    let entries = policy_payload
        .get("methods")
        .and_then(Value::as_array)
        .and_then(|methods| {
            methods
                .iter()
                .find(|m| m.get("kind").and_then(Value::as_str) == Some("recovery_unlock"))
        })
        .and_then(|method| method.get("keys"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            recovery_evidence_unbound_error(
                "bound recovery policy declares no recovery_unlock keys for recovery_unlock",
            )
        })?;
    for entry in entries {
        let Some(object) = entry.as_object() else {
            continue;
        };
        if object.get("verification_method").and_then(Value::as_str) != Some(verification_method) {
            continue;
        }
        if !recovery_key_entry_authoritative_at(object, evaluated_at) {
            return Err(recovery_evidence_unbound_error(
                "recovery key entry is revoked or outside its validity window",
            ));
        }
        return Ok(object.clone());
    }
    Err(recovery_evidence_unbound_error(
        "verification_method does not resolve to a recovery_unlock method key",
    ))
}

/// `not_before <= evaluated_at < expires_at` and (`revoked_at` is null or
/// `evaluated_at < revoked_at`).
fn recovery_key_entry_authoritative_at(
    entry: &Map<String, Value>,
    evaluated_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    let parse = |key: &str| -> Option<chrono::DateTime<chrono::Utc>> {
        entry
            .get(key)
            .and_then(Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&chrono::Utc))
    };
    let Some(not_before) = parse("not_before") else {
        return false;
    };
    let Some(expires_at) = parse("expires_at") else {
        return false;
    };
    if evaluated_at < not_before || evaluated_at >= expires_at {
        return false;
    }
    match entry.get("revoked_at") {
        Some(Value::Null) | None => true,
        Some(Value::String(_)) => parse("revoked_at").is_some_and(|revoked| evaluated_at < revoked),
        _ => false,
    }
}

/// Decode the Ed25519 key material carried by the resolved, principal-signed
/// recovery-policy entry. `verification_method` is only its stable DID URL;
/// B-model principals intentionally do not need to publish this recovery-only
/// key in their DID Document.
pub(super) fn decode_recovery_key_public_key(
    entry: &Map<String, Value>,
) -> Result<VerifyingKey, AppError> {
    let multibase = entry
        .get("public_key_multibase")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            recovery_evidence_unbound_error(
                "recovery key entry does not carry public_key_multibase",
            )
        })?;
    crate::routing::identity::device_signing::decode_ed25519_key(multibase, "multibase")
        .map_err(|error| recovery_evidence_unbound_error(format!("recovery key invalid: {error}")))
}

fn required_proof_string<'a>(
    proof: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, AppError> {
    proof
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::param_invalid(format!("proof.{key} is required")))
}

fn trusted_recovery_service_proof_body(
    proof: &Map<String, Value>,
) -> Result<TrustedRecoveryServiceProofBody, AppError> {
    let proof = serde_json::from_value::<TrustedRecoveryServiceProofBodyWithSignature>(
        Value::Object(proof.clone()),
    )
    .map_err(|error| {
        AppError::param_invalid(format!("invalid trusted_recovery_service proof: {error}"))
    })?;
    Ok(TrustedRecoveryServiceProofBody {
        kind: proof.kind,
        challenge: proof.challenge,
        service_id: proof.service_id,
        audience: proof.audience,
        verification_method: proof.verification_method,
        signature_algorithm: proof.signature_algorithm,
    })
}

fn recovery_proof_authority_error(message: impl Into<String>) -> AppError {
    crate::app_error!(SignatureInvalid, message.into())
        .with_internal_reason("recovery_proof_authority_invalid")
}

/// Canonical recovery-proof transcript binding every session-defining field.
/// Both the requesting device (when signing) and the server (when verifying)
/// MUST construct this identically.
pub(super) fn did_root_recovery_proof_transcript(
    record: &RecoverySessionServiceState,
) -> Result<DidRootRecoveryTranscript, AppError> {
    let context = typed_recovery_transcript_context(record)?;
    let transcript = DidRootRecoveryTranscript {
        schema: arkret_wire::DomainSeparationId::IDENTITY_RECOVERY_PROOF_V1.to_owned(),
        kind: RecoveryProofKind::DidRoot,
        request_id: context.request_id,
        session_grant_id: context.session_grant_id,
        session_grant_cnf_jkt: context.session_grant_cnf_jkt,
        account_id: context.account_id,
        requesting_device_id: context.requesting_device_id,
        requesting_device_public_key_did: context.requesting_device_public_key_did,
        trust_domain: context.trust_domain,
        policy_id: context.policy_id,
        policy_version: context.policy_version,
        recovery_session_id: context.recovery_session_id,
        identity_model: context.identity_model,
        model_generation_ref: context.model_generation_ref,
        publication_authority_context_digest: context.publication_authority_context_digest,
        challenge: context.challenge,
        expires_at: context.expires_at,
        // created_at is the SESSION creation/signing time (not proof time), per
        // recovery-session.schema.json $defs/did_root_transcript.
        created_at: context.created_at,
    };
    if transcript.schema != arkret_wire::DomainSeparationId::IDENTITY_RECOVERY_PROOF_V1
        || transcript.kind != RecoveryProofKind::DidRoot
    {
        return Err(AppError::internal(
            "stored did_root transcript has invalid domain or kind",
        ));
    }
    Ok(transcript)
}

pub(super) fn generic_recovery_proof_transcript(
    record: &RecoverySessionServiceState,
    proof_body: RecoveryTranscriptProofBody,
) -> Result<GenericRecoveryTranscript, AppError> {
    let context = typed_recovery_transcript_context(record)?;
    let transcript = GenericRecoveryTranscript {
        schema: arkret_wire::DomainSeparationId::IDENTITY_RECOVERY_PROOF_V1.to_owned(),
        kind: proof_body.proof_kind(),
        request_id: context.request_id,
        session_grant_id: context.session_grant_id,
        session_grant_cnf_jkt: context.session_grant_cnf_jkt,
        account_id: context.account_id,
        requesting_device_id: context.requesting_device_id,
        requesting_device_public_key_did: context.requesting_device_public_key_did,
        trust_domain: context.trust_domain,
        policy_id: context.policy_id,
        policy_version: context.policy_version,
        recovery_session_id: context.recovery_session_id,
        identity_model: context.identity_model,
        model_generation_ref: context.model_generation_ref,
        publication_authority_context_digest: context.publication_authority_context_digest,
        challenge: context.challenge,
        expires_at: context.expires_at,
        created_at: context.created_at,
        proof_body,
    };
    transcript
        .validate_shape()
        .map_err(|error| stored_recovery_type_error("generic recovery transcript", error))?;
    Ok(transcript)
}

/// Lazily expire a session whose TTL has elapsed: if a `pending`/`verified`
/// session is past `expires_at`, persist the `expired` transition and return
/// the updated record. Terminal states are returned unchanged.
pub(super) async fn expire_if_elapsed(
    state: &AppState,
    record: RecoverySessionServiceState,
) -> Result<RecoverySessionServiceState, AppError> {
    let now = chrono::Utc::now();
    let is_open = matches!(record.state, SessionState::Pending | SessionState::Verified);
    if is_open && now >= record.expires_at {
        let expired = RecoverySessionServiceState {
            state: SessionState::Expired,
            updated_at: now,
            ..record
        };
        state
            .recovery_sessions()
            .save_session(expired.clone())
            .await
            .map_err(recovery_session_store_error)?;
        return Ok(expired);
    }
    Ok(record)
}
