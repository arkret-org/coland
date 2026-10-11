use super::*;

pub(super) async fn enforce_recovery_policy_ref_typed(
    state: &AppState,
    _actor_id: &str,
    backup: &KeyBackup,
) -> Result<(), AppError> {
    let Some((ref_policy_id, ref_version)) = typed_recovery_policy_ref(backup) else {
        return Ok(());
    };

    let active = state
        .recovery_policies()
        .active_policy(backup.actor_id.as_account_id().ok_or_else(|| {
            AppError::capability_denied("recovery policy key backup requires an account actor")
        })?)
        .await
        .map_err(|error| AppError::internal(format!("recovery policy lookup failed: {error}")))?
        .ok_or_else(|| {
            AppError::conflict("no accepted recovery policy for exact backup account")
                .with_wire_code("recovery_policy_mismatch")
        })?;

    if ref_policy_id != active.policy_id.as_str() || ref_version != active.version as u64 {
        return Err(AppError::conflict(format!(
            "recovery_policy_ref {ref_policy_id:?} v{ref_version:?} does not match active policy \
             `{}` v{}",
            active.policy_id, active.version
        ))
        .with_wire_code("recovery_policy_mismatch"));
    }
    Ok(())
}

pub(super) async fn enforce_key_backup_series_chain_typed(
    state: &AppState,
    backup: &KeyBackup,
) -> Result<(), AppError> {
    let series_id = backup.series_id.as_str();
    let series_seq = backup.series_seq;
    let mut max_existing_seq: Option<u64> = None;
    let mut predecessor: Option<Value> = None;
    let supersedes = backup
        .supersedes_id
        .as_ref()
        .map(|backup_id| backup_id.as_str().to_owned());
    let snapshot = state
        .key_backups()
        .backups_for_actor(&backup.actor_id.to_string())
        .await
        .map_err(|error| {
            AppError::internal(format!("key backup series chain lookup failed: {error}"))
        })?;
    for existing in snapshot {
        if existing.get("series_id").and_then(Value::as_str) != Some(series_id) {
            continue;
        }
        if let Some(seq) = existing.get("series_seq").and_then(Value::as_u64) {
            max_existing_seq = Some(max_existing_seq.map_or(seq, |current| current.max(seq)));
        }
        if let Some(predecessor_id) = supersedes.as_deref()
            && existing.get("backup_id").and_then(Value::as_str) == Some(predecessor_id)
        {
            predecessor = Some(existing.clone());
        }
    }

    if series_seq == 0 {
        validate_series_genesis_shape_typed(backup)?;
        if let Some(existing_seq) = max_existing_seq {
            return Err(crate::app_error!(
                Conflict,
                format!(
                    "series_seq_not_monotonic: genesis envelope for series already has seq={existing_seq} persisted"
                ),
            )
            .with_reason_code(arkret_wire::ReasonCode::SERIES_SEQ_NOT_MONOTONIC));
        }
        return Ok(());
    }

    let supersedes_digest = backup
        .supersedes_digest
        .as_ref()
        .map(arkret_wire::Hash::as_str)
        .unwrap_or_default();
    if supersedes.is_none() || supersedes_digest.is_empty() {
        return Err(crate::app_error!(
            Conflict,
            "series_chain_broken: successor envelope requires `supersedes` + `supersedes_digest`",
        )
        .with_reason_code(arkret_wire::ReasonCode::SERIES_CHAIN_BROKEN));
    }
    let expected = max_existing_seq.map(|seq| seq + 1);
    if expected != Some(series_seq) {
        return Err(crate::app_error!(
            Conflict,
            format!(
                "series_seq_not_monotonic: expected series_seq={} but got {series_seq}",
                expected
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "1 (no predecessor)".to_owned())
            ),
        )
        .with_reason_code(arkret_wire::ReasonCode::SERIES_SEQ_NOT_MONOTONIC));
    }
    let Some(predecessor) = predecessor else {
        return Err(crate::app_error!(
            Conflict,
            "series_predecessor_not_found: `supersedes` references a backup_id that is not persisted",
        )
        .with_reason_code(arkret_wire::ReasonCode::SERIES_PREDECESSOR_NOT_FOUND));
    };
    let expected_digest = key_backup_canonical_digest_without_signature(&predecessor)?;
    // SOL-SEC-05 — constant-time digest comparison so a timing side channel
    // cannot leak how many leading bytes of the supersedes digest matched.
    let digests_equal = {
        use subtle::ConstantTimeEq as _;
        let left = supersedes_digest.as_bytes();
        let right = expected_digest.as_bytes();
        left.len() == right.len() && bool::from(left.ct_eq(right))
    };
    if !digests_equal {
        return Err(crate::app_error!(
            Conflict,
            "series_chain_broken: supersedes_digest does not match predecessor canonical digest",
        )
        .with_reason_code(arkret_wire::ReasonCode::SERIES_CHAIN_BROKEN));
    }
    Ok(())
}

pub(super) fn key_backup_idempotent_retry(
    existing: Option<&Value>,
    actor_id: &arkret_wire::ActorId,
    incoming: &Value,
) -> Result<bool, AppError> {
    if let Some(existing) = existing
        && !backup_actor_matches(existing, actor_id)
    {
        return Err(AppError::capability_denied(
            "backup_id is already owned by a different actor",
        ));
    }
    let Some(existing) = existing else {
        return Ok(false);
    };
    let existing_bytes = arkret_canonical::canonical_json_bytes(existing).map_err(|error| {
        AppError::internal(format!("stored key backup is not canonical: {error}"))
    })?;
    let incoming_bytes = arkret_canonical::canonical_json_bytes(incoming).map_err(|error| {
        AppError::internal(format!("key backup canonicalization failed: {error}"))
    })?;
    if existing_bytes != incoming_bytes {
        return Err(crate::app_error!(
            DuplicateConflict,
            "backup_id already exists with different canonical content",
        ));
    }
    Ok(true)
}

pub(super) async fn owned_key_backup_snapshot(
    state: &AppState,
    actor_id: &str,
) -> Result<Vec<Value>, AppError> {
    // Fail closed on DB read errors: an empty snapshot would silently skip
    // deletion eligibility checks and could let a useful recovery envelope be
    // deleted.
    let snapshot = state
        .key_backups()
        .backups_for_actor(&local_backup_actor(state, actor_id)?.to_string())
        .await
        .map_err(|error| {
            AppError::internal(format!("key backup snapshot lookup failed: {error}"))
        })?;
    Ok(snapshot)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.backups.resource.replace",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.backups.resource.replace.v1"))]
pub(super) async fn put_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    backup: JsonBody<KeyBackup>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsReplaceOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let idempotency_principal_id = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?;
    let idempotency_key = req
        .headers()
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::param_invalid("Idempotency-Key is required for key-backup PUT"))?
        .to_owned();
    if idempotency_key.len() > 128 {
        return Err(AppError::param_invalid(
            "Idempotency-Key must not exceed 128 bytes",
        ));
    }
    let backup_id = backup_id.into_inner();
    if backup_id.trim().is_empty() {
        return Err(AppError::param_invalid("backup_id is required"));
    }
    // Spec `keys-operations.schema.json#/$defs/backup_id` pins the id to
    // `ak:backup:<uuidv7>`; parse into the SDK typed id up front so a
    // non-conforming id fails before any persistence side effect.
    let typed_backup_id =
        arkret_identifiers::BackupId::new(backup_id.clone()).map_err(|error| {
            AppError::param_invalid(format!(
                "backup_id must be a ak:backup:<uuidv7> typed id: {error}"
            ))
        })?;
    // The request body is now deserialized straight into the SDK `KeyBackup`
    // type (matching `request_schema_ref: key-backup.schema.json`), so the
    // OpenAPI request contract is strong rather than `Value`.
    let backup = backup.into_inner();
    let account_actor = local_backup_actor(state, &session.actor)?;
    validate_key_backup_body_typed(&typed_backup_id, &account_actor, &backup)?;
    validate_key_backup_session_device(&backup, session.require_human_device_id())?;
    let device_gate =
        crate::routing::identity::device_generation::active_device_revocation_gate_selector(
            state,
            &session.actor,
            session.require_human_device_id(),
        )
        .await
        .map_err(|error| AppError::capability_denied(error.to_string()))?;
    state
        .persistence()
        .device_revocation_gate_status(&device_gate)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ensure_allowed()
        .map_err(|error| AppError::capability_denied(error.to_string()))?;
    let backup_value = key_backup_to_value(&backup)?;
    anchor_key_backup_auth_data_trust_root(state, &session.actor, &backup_value).await?;
    let request_hash = arkret_canonical::canonical_sha256(&backup).map_err(|error| {
        AppError::param_invalid(format!(
            "key backup body is not canonical-hashable: {error}"
        ))
    })?;
    let authenticated_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        idempotency_principal_id.clone(),
        state.service_core_id(),
    ));
    match state
        .jobs()
        .scoped_idempotency_record(
            &authenticated_actor,
            "ak.self.keys.backups.resource.replace",
            &idempotency_key,
        )
        .await
        .map_err(|error| AppError::internal(format!("idempotency lookup failed: {error}")))?
    {
        Some(record) if record.request_hash == request_hash => {
            let outcome = serde_json::from_value(record.response_body).map_err(|error| {
                AppError::internal(format!(
                    "stored key-backup replay outcome is invalid: {error}"
                ))
            })?;
            return json_ok(outcome);
        }
        Some(_) => {
            return Err(crate::app_error!(
                DuplicateConflict,
                "Idempotency-Key was reused with a different key-backup body",
            ));
        }
        None => {}
    }
    enforce_recovery_policy_ref_typed(state, &session.actor, &backup).await?;
    if backup.encryption.recipient_method == KeyBackupRecipientMethod::RecoveryPublicKey {
        validate_current_recovery_recipient(state, &backup, chrono::Utc::now()).await?;
    }
    let ciphertext_digest = backup.ciphertext_digest.clone();
    let existing = state
        .key_backups()
        .backup(&backup_id)
        .await
        .map_err(|error| AppError::internal(format!("key backup lookup failed: {error}")))?;
    let duplicate = key_backup_idempotent_retry(existing.as_ref(), &account_actor, &backup_value)?;
    if duplicate {
        let outcome = KeysBackupsReplaceOutcome {
            status: KeyBackupPutStatus::Duplicate,
            backup_id: typed_backup_id,
            ciphertext_digest,
        };
        persist_key_backup_idempotency(
            state,
            &idempotency_principal_id,
            &idempotency_key,
            &request_hash,
            &outcome,
        )
        .await;
        return json_ok(outcome);
    }
    enforce_key_backup_series_chain_typed(state, &backup).await?;
    state
        .key_backups()
        .store_backup(backup_id.clone(), backup_value)
        .await
        .map_err(|error| {
            // SOL-02-004 — the UNIQUE(series_actor_id, series_id, series_seq)
            // constraint rejected a concurrent successor double-write. The
            // storage layer is now the authoritative race guard for §7.6
            // monotonicity; the loser is told the seq is already taken.
            if error.is_conflict_kind() {
                crate::app_error!(
                    SchemaViolation,
                    format!("series_seq_not_monotonic: {}", error.detail()),
                )
                .with_reason_code("series_seq_not_monotonic")
            } else {
                AppError::internal(error.to_string())
            }
        })?;
    let outcome = KeysBackupsReplaceOutcome {
        status: KeyBackupPutStatus::Accepted,
        backup_id: typed_backup_id,
        ciphertext_digest,
    };
    persist_key_backup_idempotency(
        state,
        &idempotency_principal_id,
        &idempotency_key,
        &request_hash,
        &outcome,
    )
    .await;
    json_ok(outcome)
}

async fn persist_key_backup_idempotency(
    state: &AppState,
    principal_id: &arkret_wire::DidCoreId,
    idempotency_key: &str,
    request_hash: &str,
    outcome: &KeysBackupsReplaceOutcome,
) {
    let created_at = chrono::Utc::now();
    let response_body = match serde_json::to_value(outcome) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, idempotency_key, "key-backup replay outcome serialization failed");
            return;
        }
    };
    let record = coland_services::jobs::IdempotencyState {
        authenticated_actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            principal_id.clone(),
            state.service_core_id(),
        )),
        operation_id: "ak.self.keys.backups.resource.replace".to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        request_hash: request_hash.to_owned(),
        response_status: StatusCode::OK.as_u16() as i32,
        response_body,
        created_at,
        expires_at: created_at + chrono::Duration::hours(24),
    };
    if let Err(error) = state.jobs().store_idempotency_record(record).await {
        tracing::warn!(%error, idempotency_key, "key-backup idempotency outcome persist failed");
    }
}

#[salvo::oapi::endpoint(operation_id = "ak.self.keys.backups.command.unlock", tags("identity"))]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.backups.command.unlock.v1"))]
pub(super) async fn unlock_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    body: JsonBody<KeysBackupsUnlockRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeyBackup> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let backup_id = backup_id.into_inner();
    // spec `keys_backups_unlock_request_body` (additionalProperties: false):
    // `{proof}` only; the unlock proof MUST NOT travel in a header or query.
    let body = body.into_inner();
    let proof = serde_json::to_value(&body.proof).map_err(|error| {
        AppError::internal(format!("key backup unlock proof serialize: {error}"))
    })?;
    let request_digest = arkret_canonical::canonical_sha256(&body)
        .map_err(|error| AppError::internal(error.to_string()))?;
    let holder = session
        .session_grant
        .as_ref()
        .map(|grant| format!("{}:{}", grant.grant_id, grant.cnf_jkt))
        .unwrap_or_else(|| session.require_human_device_id().clone());
    if let arkret_models_crypto::KeyBackupUnlockAuthority::RecoverySession {
        recovery_session_id,
    } = &body.proof.authority
    {
        let grant = session
            .session_grant
            .as_ref()
            .ok_or_else(|| AppError::capability_denied("recovery grant required"))?;
        if grant.credential_class
            != arkret_models_identity::SessionGrantCredentialClass::RecoverySession
        {
            return Err(AppError::capability_denied("recovery grant required"));
        }
        if !state
            .key_backups()
            .reserve_recovery_unlock_attempt(
                recovery_session_id.as_str(),
                &holder,
                &request_digest,
                Utc::now(),
            )
            .await
            .map_err(|error| AppError::capability_denied(error.to_string()))?
        {
            tracing::warn!(recovery_session_id=%recovery_session_id, "recovery backup unlock attempt rate exceeded");
            return Err(crate::app_error!(
                RateLimited,
                "recovery unlock attempt rate limit"
            ));
        }
    }
    let Some(backup) = state
        .key_backups()
        .backup(&backup_id)
        .await
        .map_err(|error| AppError::internal(format!("key backup lookup failed: {error}")))?
    else {
        return Err(AppError::not_found("key backup not found"));
    };
    if !backup_actor_matches(&backup, &local_backup_actor(state, &session.actor)?) {
        return Err(AppError::not_found("key backup not found"));
    }
    // The path `backup_id` and `proof.backup_id` MUST match: the envelope is
    // looked up by the path id and the shape check below requires
    // `proof.backup_id` to equal the envelope's own `backup_id`.
    if let Err(error) = verify_key_backup_unlock_proof(state, &proof, &session, &backup).await {
        tracing::warn!(actor=%session.actor, device=%session.require_human_device_id(), %backup_id, %request_digest, %error, "key backup unlock proof rejected");
        return Err(error);
    }
    // key-management.md §7.4.1 - anchor the released envelope's auth_data.signature
    // to the actor's current device trust root before returning the full ciphertext.
    // Without this, a malicious/compromised server could substitute an envelope
    // signed by a revoked old device key; such envelopes MUST be rejected as
    // `untrusted_backup_signature` even when series chain / ciphertext_digest match.
    anchor_key_backup_auth_data_trust_root(state, &session.actor, &backup).await?;
    let basis = match &body.proof.authority {
        arkret_models_crypto::KeyBackupUnlockAuthority::CurrentDevice { .. } => {
            coland_storage::KeyBackupUnlockBasis::CurrentDevice {
                basis: unlock_active_basis(state, &body.proof.account_id, &backup).await?,
                device_id: body.proof.requesting_device_id.clone(),
            }
        }
        arkret_models_crypto::KeyBackupUnlockAuthority::RecoverySession { .. } => {
            coland_storage::KeyBackupUnlockBasis::RecoverySession
        }
    };
    let authority_id = match &body.proof.authority {
        arkret_models_crypto::KeyBackupUnlockAuthority::CurrentDevice { challenge_id, .. } => {
            challenge_id.as_str()
        }
        arkret_models_crypto::KeyBackupUnlockAuthority::RecoverySession {
            recovery_session_id,
        } => recovery_session_id.as_str(),
    };
    let backup = state
        .key_backups()
        .consume_unlock(coland_storage::KeyBackupUnlockCommand {
            basis: &basis,
            authority_id,
            backup,
            request_digest: &request_digest,
            holder: &holder,
            ip: &unlock_client_ip(req),
            now: Utc::now(),
            daily_limit: state.config().key_backup_daily_download_limit,
        })
        .await
        .map_err(unlock_consumption_error)?;
    let backup = serde_json::from_value(backup)
        .map_err(|error| AppError::internal(format!("stored key backup invalid: {error}")))?;
    json_ok(backup)
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.backups.resource.delete",
    tags("identity")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.keys.backups.resource.delete.v1"))]
pub(super) async fn delete_key_backup(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<KeysBackupsDeleteOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let idempotency_principal_id = arkret_wire::DidCoreId::new(session.actor.clone())
        .map_err(|error| AppError::internal(format!("session actor invalid: {error}")))?;
    let backup_id = backup_id.into_inner();
    // spec `keys_backups_delete_request_body` (additionalProperties: false):
    // `{request_id, challenge_id, proof, reason?}` travels in the JSON body,
    // never a header.
    let body = req
        .parse_json::<KeysBackupsDeleteRequestBody>()
        .await
        .map_err(|error| {
            AppError::param_invalid(format!(
                "ak.self.keys.backups.resource.delete.v1 request body is invalid: {error}"
            ))
        })?;
    // The closed `keys_backups_delete_proof` admits only the three high-risk
    // branches; reject the ordinary device branch as a body defect before any
    // idempotency, challenge or pointer read.
    super::delete::require_high_risk_delete_proof(&body)?;

    // key-management.md §7.8.1 step 4. The ledger is keyed on
    // `(principal_id, backup_id, request_id)`, so an identical network retry
    // replays the stored terminal outcome instead of re-verifying an already
    // consumed challenge, and the same `request_id` with a different body is a
    // duplicate conflict. This is what lets "single-use challenge" coexist with
    // the registry's retry-safe DELETE.
    let idempotency_key = format!(
        "{}:{backup_id}:{}",
        KEY_BACKUP_DELETE_OPERATION,
        body.request_id.as_str()
    );
    let request_hash = arkret_canonical::canonical_sha256(&body).map_err(|error| {
        AppError::param_invalid(format!(
            "delete request body is not canonical-hashable: {error}"
        ))
    })?;
    let authenticated_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        idempotency_principal_id.clone(),
        state.service_core_id(),
    ));
    match state
        .jobs()
        .scoped_idempotency_record(
            &authenticated_actor,
            "ak.self.keys.backups.resource.delete",
            &idempotency_key,
        )
        .await
    {
        Ok(Some(record)) if record.request_hash == request_hash => {
            let outcome: KeysBackupsDeleteOutcome = serde_json::from_value(record.response_body)
                .map_err(|error| {
                    AppError::internal(format!("stored delete outcome is corrupt: {error}"))
                })?;
            return json_ok(outcome);
        }
        Ok(Some(_)) => {
            return Err(AppError::conflict(
                "request_id was reused with a different delete request body",
            )
            .with_wire_code("duplicate_conflict"));
        }
        Ok(None) => {}
        Err(error) => {
            return Err(AppError::internal(format!(
                "delete idempotency lookup failed: {error}"
            )));
        }
    }

    let account_actor = local_backup_actor(state, &session.actor)?;
    let owned_backup = state
        .key_backups()
        .backup(&backup_id)
        .await
        .map_err(|error| AppError::internal(format!("key backup lookup failed: {error}")))?
        .filter(|backup| backup_actor_matches(backup, &account_actor));
    let Some(backup) = owned_backup else {
        // spec `keys_backups_delete_outcome` models `deleted: const true` only;
        // a backup that does not exist (or is not owned by this actor) cannot be
        // represented as a success outcome, so report it as not-found.
        return Err(AppError::not_found("key backup not found"));
    };
    let now = chrono::Utc::now();
    let authorized =
        authorize_key_backup_delete(state, &body, &backup_id, &session.actor, now).await?;
    ensure_key_backup_delete_allowed(state, &session.actor, &backup).await?;
    // Policy/session validation, single-use challenge and exact backup deletion
    // share one storage transaction, including rollback on a changed object.
    consume_key_backup_delete_challenge(state, &authorized, backup.clone(), now).await?;
    append_audit_log(
        state,
        Some(&session.actor),
        arkret_wire::event_kind_str::AUDIT_ACCESSED,
        json!({
            "access_kind": "key_backup_delete",
            "backup_id": backup_id.clone(),
            "device_id": session.require_human_device_id(),
            "backup_kind": backup.get("backup_kind").cloned().unwrap_or(Value::Null),
            "series_id": backup.get("series_id").cloned().unwrap_or(Value::Null),
            "series_seq": backup.get("series_seq").cloned().unwrap_or(Value::Null),
            // Which of the three §7.8 authority branches carried this delete.
            "delete_proof_kind": authorized.proof_branch,
        }),
        "deleted",
    )
    .await;
    let outcome = KeysBackupsDeleteOutcome {
        deleted: true,
        backup_id: BackupId::new(backup_id).ok(),
    };
    record_delete_idempotency(
        state,
        &idempotency_principal_id,
        &idempotency_key,
        &request_hash,
        &outcome,
    )
    .await;
    json_ok(outcome)
}

/// Persist the terminal outcome so an identical retry replays it.
///
/// A persist failure is logged rather than surfaced: the delete has already
/// happened, and turning a successful delete into a 5xx would be worse than
/// losing the replay shortcut (the retry then hits the consumed challenge and
/// fails closed, which is safe).
async fn record_delete_idempotency(
    state: &AppState,
    actor_id: &arkret_wire::DidCoreId,
    idempotency_key: &str,
    request_hash: &str,
    outcome: &KeysBackupsDeleteOutcome,
) {
    let Ok(response_body) = serde_json::to_value(outcome) else {
        return;
    };
    let created_at = chrono::Utc::now();
    let record = coland_services::jobs::IdempotencyState {
        authenticated_actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            actor_id.clone(),
            state.service_core_id(),
        )),
        operation_id: "ak.self.keys.backups.resource.delete".to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        request_hash: request_hash.to_owned(),
        response_status: 200,
        response_body,
        created_at,
        expires_at: created_at
            + chrono::Duration::seconds(KEY_BACKUP_DELETE_IDEMPOTENCY_TTL_SECONDS),
    };
    if let Err(error) = state.jobs().store_idempotency_record(record).await {
        tracing::warn!(%error, idempotency_key, "key backup delete idempotency persist failed");
    }
}

/// Map a refusal of the consuming transaction onto the unlock operation's
/// registered failures: a moved pointer, series or generation is
/// `backup_revision_stale`, and a device that stopped being current keeps its
/// device code.
fn unlock_consumption_error(error: coland_services::ServiceError) -> AppError {
    use coland_storage::ConflictCode;

    match error.conflict_code() {
        Some(ConflictCode::BackupRevisionStale) => {
            super::unlock::backup_revision_stale(&error.to_string())
        }
        Some(
            code @ (ConflictCode::DeviceRevoked
            | ConflictCode::DeviceRevocationPending
            | ConflictCode::DeviceGenerationFenced
            | ConflictCode::DeviceUnauthorized),
        ) => arkret_wire::ErrorCode::from_wire(code.as_str()).map_or_else(
            || AppError::capability_denied(error.to_string()),
            |registered| AppError::from_rejection(registered, error.to_string()),
        ),
        Some(ConflictCode::TemporarilyUnavailable) => {
            crate::app_error!(TemporarilyUnavailable, error.to_string())
        }
        _ if error.to_string().contains("rate_limited") => {
            crate::app_error!(RateLimited, "backup unlock rate limit")
        }
        _ => AppError::conflict(error.to_string()),
    }
}

fn unlock_client_ip(req: &Request) -> String {
    crate::ratelimit::trusted_forwarded_client(req).unwrap_or_else(|| {
        req.remote_addr()
            .as_ipv4()
            .map(|address| address.ip().to_string())
            .or_else(|| {
                req.remote_addr()
                    .as_ipv6()
                    .map(|address| address.ip().to_string())
            })
            .unwrap_or_else(|| "unknown".to_owned())
    })
}
