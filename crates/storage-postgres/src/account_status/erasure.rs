//! One physical Account-private erasure and its original signed completion.

use arkret_models_collaboration::events_payloads::event_wire::ErasureTrigger;
use arkret_models_collaboration::governance::erasure::{
    ErasedClass, ErasureAttemptOutcome, ErasureStorageBoundary, ErasureSubjectKind,
};
use coland_storage::{
    AccountErasureCompletionSigner, AccountErasureExecution, AccountErasureExecutionState,
    IdempotencyRecord,
};

use super::*;
use crate::AsyncPgConnection;

mod private_rows;

#[cfg(test)]
mod completion_tests;

#[derive(QueryableByName)]
struct ExecutionRow {
    #[diesel(sql_type = Jsonb)]
    response_body: serde_json::Value,
    #[diesel(sql_type = Text)]
    request_hash: String,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

fn refused(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}

async fn execution_row(
    conn: &mut AsyncPgConnection,
    pending: &AccountErasureExecution,
    phase: AccountErasureExecutionState,
) -> PersistenceResult<Option<ExecutionRow>> {
    let actor = arkret_wire::ActorId::service(pending.receiver_id.clone());
    sql_query("SELECT response_body,request_hash,created_at FROM idempotency_keys WHERE actor_key=$1 AND operation_id=$2 AND idempotency_key=$3 FOR UPDATE")
        .bind::<Text, _>(actor.canonical_key().map_err(PersistenceError::database)?)
        .bind::<Text, _>(coland_storage::INTERNAL_IDEMPOTENCY_OPERATION)
        .bind::<Text, _>(pending.key(phase))
        .get_result::<ExecutionRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)
}

/// Accepted, proof-verified record/receipt pairs can create only a reject-only
/// projection. No HMAC key, local handle, PCR, or login credential is created.
pub(super) async fn retain_reject_only_account_projection(
    conn: &mut AsyncPgConnection,
    terminal: &AccountStatusRecord,
    receipt: &AccountStatusReceipt,
) -> PersistenceResult<()> {
    crate::pcr_private_authority::lock_account_private_tuple_for_erasure(
        conn,
        &terminal.account_id,
    )
    .await?;
    sql_query("WITH owner AS (INSERT INTO accounts(principal_id,station_id,disabled_at,created_at,updated_at) VALUES($1,$2,$3,$3,$3) ON CONFLICT(station_id,principal_id) DO UPDATE SET disabled_at=COALESCE(accounts.disabled_at,EXCLUDED.disabled_at) RETURNING pk) INSERT INTO account_lifecycle(account_pk,state,reason,changed_at) SELECT pk,'erasure_pending','account_status_erasure',$3 FROM owner ON CONFLICT(account_pk) DO UPDATE SET state='erasure_pending',reason=EXCLUDED.reason,changed_at=EXCLUDED.changed_at")
        .bind::<Text,_>(terminal.account_id.principal_id.as_str())
        .bind::<Text,_>(terminal.account_id.station_id.as_str())
        .bind::<Timestamptz,_>(terminal.issued_at)
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    let pending = AccountErasureExecution {
        receiver_id: receipt.receiver_id.clone(),
        account_authority_id: terminal.account_authority_id.clone(),
        account_id: terminal.account_id.clone(),
        principal_id: terminal.account_id.principal_id.clone(),
        triggering_status_record_id: terminal.account_status_record_id.clone(),
        storage_boundary: ErasureStorageBoundary::AccountPrivateStore,
        state: AccountErasureExecutionState::Pending,
        package: None,
    };
    let intent = IdempotencyRecord {
        authenticated_actor: arkret_wire::ActorId::service(receipt.receiver_id.clone()),
        operation_id: coland_storage::INTERNAL_IDEMPOTENCY_OPERATION.into(),
        idempotency_key: pending.key(AccountErasureExecutionState::Pending),
        request_hash: pending.request_hash()?,
        response_status: 202,
        response_body: serde_json::to_value(&pending).map_err(PersistenceError::database)?,
        created_at: receipt.accepted_at,
        expires_at: receipt.accepted_at + chrono::Duration::days(36_500),
    };
    crate::idempotency::record_exact_idempotency_in_connection(conn, &intent).await?;
    Ok(())
}

fn validate_pending(pending: &AccountErasureExecution) -> PersistenceResult<()> {
    if pending.state != AccountErasureExecutionState::Pending
        || pending.package.is_some()
        || pending.principal_id != pending.account_id.principal_id
        || pending.storage_boundary != ErasureStorageBoundary::AccountPrivateStore
    {
        return Err(refused(
            "erasure does not name one receiver pending Account-private intent",
        ));
    }
    Ok(())
}

async fn accepted_intent(
    conn: &mut AsyncPgConnection,
    pending: &AccountErasureExecution,
) -> Result<(AccountStatusRecord, ExecutionRow, String), PgTransactionError> {
    // The accepted terminal record is absorbing. Its existing replica
    // advisory serializes exact execution without locking the public PCR.
    let row = sql_query("SELECT record,receipt FROM account_status_replica_records WHERE account_authority_id=$1 AND account_id=$2 ORDER BY status_sequence DESC LIMIT 1")
            .bind::<Text, _>(pending.account_authority_id.as_str())
            .bind::<Jsonb, _>(encode_account_id(&pending.account_id)?)
            .get_result::<RecordRow>(&mut *conn).await?;
    let record = decode_record(&row)?;
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(format!(
            "account-status:{}:{}",
            pending.account_authority_id, pending.account_id
        ))
        .execute(&mut *conn)
        .await?;
    let row = sql_query("SELECT record,receipt FROM account_status_replica_records WHERE account_authority_id=$1 AND account_id=$2 ORDER BY status_sequence DESC LIMIT 1 FOR SHARE")
            .bind::<Text, _>(pending.account_authority_id.as_str())
            .bind::<Jsonb, _>(encode_account_id(&pending.account_id)?)
            .get_result::<RecordRow>(&mut *conn).await?;
    let terminal = decode_record(&row)?;
    let receipt = decode_receipt(&row)?;
    receipt
        .validate_for_record(&terminal)
        .map_err(PersistenceError::database)?;
    if terminal != record
        || terminal.account_status_record_id != pending.triggering_status_record_id
        || terminal.status
            != arkret_models_collaboration::objects::account_status::AccountStatus::ErasurePending
        || terminal.account_id != pending.account_id
        || terminal.account_authority_id != pending.account_authority_id
        || receipt.receiver_id != pending.receiver_id
    {
        return Err(
            refused("erasure source is not the exact accepted terminal Account record").into(),
        );
    }
    let expected_hash = pending.request_hash()?;
    let intent = execution_row(conn, pending, AccountErasureExecutionState::Pending)
        .await?
        .ok_or_else(|| refused("the accepted erasure execution intent is unavailable"))?;
    let original: AccountErasureExecution =
        serde_json::from_value(intent.response_body.clone()).map_err(PersistenceError::database)?;
    if original != *pending || intent.request_hash != expected_hash {
        return Err(refused("erasure execution differs from its durable accepted intent").into());
    }
    Ok((terminal, intent, expected_hash))
}

pub(super) async fn complete(
    pool: &PgPool,
    pending: &AccountErasureExecution,
    sign: AccountErasureCompletionSigner<'_>,
) -> PersistenceResult<AccountErasureExecution> {
    validate_pending(pending)?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        let (_terminal,intent,expected_hash)=accepted_intent(conn,pending).await?;
        if let Some(original) = execution_row(conn, pending, AccountErasureExecutionState::Completed).await? {
            let completed: AccountErasureExecution = serde_json::from_value(original.response_body)
                .map_err(PersistenceError::database)?;
            let mut expected = completed.clone();
            expected.state = AccountErasureExecutionState::Pending;
            expected.package = None;
            if original.request_hash != expected_hash || expected != *pending
                || completed.state != AccountErasureExecutionState::Completed {
                return Err(refused("erasure completion is bound to another accepted intent").into());
            }
            // The only writer below validated and atomically retained this
            // exact signed package. A retry never signs or erases a second time.
            completed.package.as_ref().ok_or_else(|| refused("completed erasure has no original receipt"))?
                .validate_bindings().map_err(PersistenceError::database)?;
            return Ok(completed);
        }
        crate::pcr_private_authority::lock_account_private_tuple_for_erasure(conn,&pending.account_id).await?;
        sql_query("SELECT to_jsonb(a) AS payload FROM accounts a WHERE a.principal_id=$1 AND a.station_id=$2 FOR UPDATE OF a")
            .bind::<Text, _>(pending.account_id.principal_id.as_str())
            .bind::<Text, _>(pending.account_id.station_id.as_str())
            .get_result::<crate::query_rows::JsonPayloadRow>(&mut *conn).await?;
        // Profile and handle projections belong to the same physical purge.
        // The Account tuple, PCR binding and governance history remain intact.
        sql_query("INSERT INTO handle_releases(localpart,released_at) SELECT lp.localpart,NOW() FROM account_localparts lp JOIN accounts a ON a.pk=lp.account_pk WHERE a.principal_id=$1 AND a.station_id=$2 ON CONFLICT(localpart) DO UPDATE SET released_at=EXCLUDED.released_at")
            .bind::<Text, _>(pending.account_id.principal_id.as_str())
            .bind::<Text, _>(pending.account_id.station_id.as_str())
            .execute(&mut *conn).await?;
        sql_query("DELETE FROM account_localparts lp USING accounts a WHERE lp.account_pk=a.pk AND a.principal_id=$1 AND a.station_id=$2")
            .bind::<Text, _>(pending.account_id.principal_id.as_str())
            .bind::<Text, _>(pending.account_id.station_id.as_str())
            .execute(&mut *conn).await?;
        sql_query("UPDATE accounts SET display_name='[user erased]',payload='{}'::jsonb,updated_at=NOW() WHERE principal_id=$1 AND station_id=$2")
            .bind::<Text, _>(pending.account_id.principal_id.as_str())
            .bind::<Text, _>(pending.account_id.station_id.as_str())
            .execute(&mut *conn).await?;
        // Account erasure, unlike consent revocation, also drops the whole
        // private seen-source ledger and its per-Account HMAC key.
        sql_query("WITH holder AS (SELECT pk FROM accounts WHERE principal_id=$1 AND station_id=$2), erased_ledger AS (DELETE FROM invite_new_source_ledgers WHERE account_pk IN (SELECT pk FROM holder)) DELETE FROM invite_new_source_hmac_keys WHERE account_pk IN (SELECT pk FROM holder)")
            .bind::<Text, _>(pending.account_id.principal_id.as_str())
            .bind::<Text, _>(pending.account_id.station_id.as_str())
            .execute(&mut *conn).await?;
        let actor = arkret_wire::ActorId::account(pending.account_id.clone());
        crate::key_backup::lock_backup_series_in_connection(conn, &actor).await?;
        let actor_key = actor.to_string();
        let account_key = pending.account_id.to_string();
        // Derived private rows are removed before their immutable signed
        // source. The trigger permits only this accepted terminal Account.
        for statement in [
            "DELETE FROM device_push_routes WHERE account_key=$1",
            "DELETE FROM read_cursor_winners WHERE account_key=$1",
            "DELETE FROM agent_action_rejections WHERE controller_account_key=$1",
            "DELETE FROM agent_action_requests WHERE controller_account_key=$1",
            "DELETE FROM agent_draft_pending_intents WHERE controller_account_key=$1",
        ] {
            sql_query(statement).bind::<Text, _>(&account_key).execute(&mut *conn).await?;
        }
        sql_query("DELETE FROM key_backup_unlock_entries WHERE authority_id IN (SELECT authority_id FROM key_backup_unlock_authorities WHERE account_id=$1)")
            .bind::<Text, _>(&account_key).execute(&mut *conn).await?;
        sql_query("DELETE FROM key_backup_unlock_authorities WHERE account_id=$1")
            .bind::<Text, _>(&account_key).execute(&mut *conn).await?;
        sql_query("DELETE FROM key_backup_delete_challenges WHERE principal_id=$1 AND station_id=$2")
            .bind::<Text, _>(pending.account_id.principal_id.as_str())
            .bind::<Text, _>(pending.account_id.station_id.as_str())
            .execute(&mut *conn).await?;
        sql_query("DELETE FROM key_backups WHERE actor_id=$1")
            .bind::<Text, _>(&actor_key)
            .execute(&mut *conn).await?;
        for statement in [
            "DELETE FROM account_datas WHERE actor_id=$1",
            "DELETE FROM account_data_changes WHERE actor_id=$1",
            "DELETE FROM account_data_change_retention WHERE actor_id=$1",
        ] {
            sql_query(statement).bind::<Text, _>(&actor_key).execute(&mut *conn).await?;
        }
        sql_query("DELETE FROM actor_private_events WHERE actor_private_event_owner(envelope)=$1")
            .bind::<Jsonb,_>(serde_json::to_value(&pending.account_id).map_err(PersistenceError::database)?)
            .execute(&mut *conn).await?;
        private_rows::purge(conn, &pending.account_id).await?;
        // Source deletion and derived trigger work precede the final complete
        // removal of this Account's historical private MVCC payloads.
        for statement in [
            "DELETE FROM account_global_versions WHERE actor_key=$1",
            "DELETE FROM account_global_channel_clocks WHERE actor_key=$1",
        ] {
            sql_query(statement).bind::<Text, _>(&actor_key).execute(&mut *conn).await?;
        }
        sql_query("DELETE FROM idempotency_keys WHERE authenticated_actor=$1 AND source_event_pk IS NULL")
            .bind::<Jsonb, _>(serde_json::to_value(&actor).map_err(PersistenceError::database)?)
            .execute(&mut *conn).await?;
        let completed_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let package = sign(completed_at)?;
        package.validate_bindings().map_err(PersistenceError::database)?;
        let receipt = &package.receipt;
        let classes = [ErasedClass::AccountPrivateState, ErasedClass::PushRoutes, ErasedClass::DeviceSecrets, ErasedClass::ProjectionRows];
        if receipt.issuer_id != pending.receiver_id
            || receipt.trigger != (ErasureTrigger::AccountStatusRecord { account_status_record_id: pending.triggering_status_record_id.clone() })
            || receipt.subject.kind != ErasureSubjectKind::Principal
            || receipt.subject.subject_ref != pending.principal_id.as_str()
            || receipt.scope.storage_boundary != pending.storage_boundary
            || receipt.scope.realm_id.is_some()
            || receipt.scope.retention_policy_id.is_some()
            || receipt.legal_hold_ref.is_some()
            || receipt.scope.target_refs != [pending.principal_id.to_string()]
            || receipt.scope.service_scope.as_deref() != Some("account_status.erasure_execution")
            || receipt.outcome != ErasureAttemptOutcome::Completed
            || receipt.erased_classes.len() != classes.len()
            || classes.iter().any(|class| !receipt.erased_classes.contains(class))
            || receipt.completed_at != completed_at
        {
            return Err(refused("signed completion changed its physical Account-private execution").into());
        }
        let mut completed = pending.clone();
        completed.state = AccountErasureExecutionState::Completed;
        completed.package = Some(package);
        let completed_record = IdempotencyRecord {
            authenticated_actor: arkret_wire::ActorId::service(pending.receiver_id.clone()),
            operation_id: coland_storage::INTERNAL_IDEMPOTENCY_OPERATION.into(),
            idempotency_key: pending.key(AccountErasureExecutionState::Completed),
            request_hash: expected_hash,
            response_status: 200,
            response_body: serde_json::to_value(&completed).map_err(PersistenceError::database)?,
            created_at: intent.created_at,
            expires_at: intent.created_at + chrono::Duration::days(36_500),
        };
        crate::idempotency::record_exact_idempotency_in_connection(conn, &completed_record).await?;
        Ok(completed)
    }).await.map_err(PgTransactionError::into_persistence)
}
