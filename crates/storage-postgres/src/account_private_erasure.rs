//! Exact Account-private write fencing and physical-erasure custody.
use arkret_models_collaboration::account_status::AccountStatusRecord;
use arkret_models_collaboration::events_payloads::event_wire::ErasureTrigger;
use arkret_models_collaboration::governance::erasure::{
    ErasedClass, ErasureAttemptOutcome, ErasureReceiptPackage, ErasureStorageBoundary,
    ErasureSubjectKind,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_wire::AccountId;
use coland_storage::AccountPrivateErasureReceiptIssuer;

use crate::{
    AsyncConnection, AsyncPgConnection, BigInt, Bool, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz,
    pg_conn, sql_query,
};

/// The producer's durable completion index, exposed separately from mutation APIs.
pub struct PgAccountPrivateErasureCompletionStore {
    pub pool: PgPool,
}

#[async_trait::async_trait]
impl coland_storage::AccountPrivateErasureCompletionStore
    for PgAccountPrivateErasureCompletionStore
{
    async fn receipt_id(
        &self,
        account: &AccountId,
        record_id: &arkret_wire::AccountStatusRecordId,
        executor_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<arkret_wire::ReceiptId>> {
        let mut conn = pg_conn(&self.pool).await?;
        let original = sql_query("SELECT triggering_status_record_id,package FROM account_private_erasure_completions WHERE account_id=$1")
            .bind::<Jsonb, _>(serde_json::to_value(account).map_err(PersistenceError::database)?)
            .get_result::<CompletionOriginal>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let Some(original) = original else {
            return Ok(None);
        };
        if original.triggering_status_record_id != record_id.as_str() {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: stored Account completion belongs to another terminal record"
                    .to_owned(),
            ));
        }
        let package: ErasureReceiptPackage =
            serde_json::from_value(original.package).map_err(PersistenceError::database)?;
        validate_completed_package(
            &package,
            account,
            record_id,
            executor_id,
            package.receipt.completed_at,
        )?;
        Ok(Some(
            arkret_wire::ReceiptId::new(package.receipt.receipt_id)
                .map_err(PersistenceError::database)?,
        ))
    }
}

#[derive(QueryableByName)]
struct PrivateWriteDecision {
    #[diesel(sql_type=Bool)]
    writable: bool,
}

/// Take this fence after authority locks and before private payload row locks.
/// The caller must own a real transaction; an autocommit SELECT cannot fence
/// a subsequent write. Derived publishers may skip a completed recipient.
pub(crate) async fn lock_private_storage_in_connection(
    conn: &mut AsyncPgConnection,
    owner: &AccountId,
) -> PersistenceResult<bool> {
    Ok(
        sql_query("SELECT public.lock_account_private_storage($1) AS writable")
            .bind::<Jsonb, _>(serde_json::to_value(owner).map_err(PersistenceError::database)?)
            .get_result::<PrivateWriteDecision>(conn)
            .await
            .map_err(PersistenceError::database)?
            .writable,
    )
}

pub(crate) async fn require_private_write_in_connection(
    conn: &mut AsyncPgConnection,
    owner: &AccountId,
) -> PersistenceResult<()> {
    if !lock_private_storage_in_connection(conn, owner).await? {
        return Err(PersistenceError::Conflict(
            "failed_precondition: account-private storage has been erased".to_owned(),
        ));
    }
    let pending=sql_query("SELECT EXISTS(SELECT 1 FROM account_status_replica_records WHERE account_id=$1 AND record->>'status'='erasure_pending') AS writable")
        .bind::<Jsonb,_>(serde_json::to_value(owner).map_err(PersistenceError::database)?)
        .get_result::<PrivateWriteDecision>(&mut *conn).await.map_err(PersistenceError::database)?;
    if pending.writable {
        return Err(PersistenceError::Conflict(
            "failed_precondition: account erasure is irrevocably pending".to_owned(),
        ));
    }
    Ok(())
}

/// Identity-row writers must acquire UPDATE immediately. Taking SHARE and
/// upgrading later would deadlock two profile writers or a concurrent eraser.
pub(crate) async fn require_identity_write_in_connection(
    conn: &mut AsyncPgConnection,
    owner: &AccountId,
) -> PersistenceResult<()> {
    sql_query("SELECT pk FROM accounts WHERE principal_id=$1 AND station_id=$2 FOR UPDATE")
        .bind::<Text, _>(owner.principal_id.as_str())
        .bind::<Text, _>(owner.station_id.as_str())
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    require_private_write_in_connection(conn, owner).await
}

#[derive(QueryableByName)]
struct AcceptedStatus {
    #[diesel(sql_type=Jsonb)]
    record: serde_json::Value,
}

#[derive(QueryableByName)]
struct OwnedAccount {
    #[diesel(sql_type=BigInt)]
    pk: i64,
}

#[derive(QueryableByName)]
struct CompletionOriginal {
    #[diesel(sql_type=Text)]
    triggering_status_record_id: String,
    #[diesel(sql_type=Jsonb)]
    package: serde_json::Value,
}

#[derive(QueryableByName)]
struct CompletionTime {
    #[diesel(sql_type=Timestamptz)]
    completed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct VerifiedPushRevocation {
    #[diesel(sql_type=Text)]
    source_station_id: arkret_wire::DidCoreId,
    #[diesel(sql_type=Text)]
    destination_gateway_id: arkret_wire::DidCoreId,
    #[diesel(sql_type=crate::Binary)]
    canonical_request: Vec<u8>,
    #[diesel(sql_type=Text)]
    request_digest: String,
    #[diesel(sql_type=Jsonb)]
    receipt: serde_json::Value,
}

async fn retain_verified_gateway_revocations(
    conn: &mut AsyncPgConnection,
    account: &AccountId,
    record: &arkret_wire::AccountStatusRecordId,
    issuer: &arkret_wire::DidCoreId,
) -> PersistenceResult<()> {
    use arkret_models_integration::{
        PushRegistrationHandoffRequestBody, PushRegistrationInstallationReceipt,
    };
    let account_json = serde_json::to_value(account).map_err(PersistenceError::database)?;
    let rows=sql_query("SELECT source_station_id,destination_gateway_id,canonical_request,request_digest,receipt FROM push_registration_handoff_intents WHERE local_account_id=$1 AND desired_state='revoked' AND status='receipt_verified'")
        .bind::<Jsonb,_>(&account_json).load::<VerifiedPushRevocation>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in rows {
        let request: PushRegistrationHandoffRequestBody =
            serde_json::from_slice(&row.canonical_request).map_err(PersistenceError::database)?;
        if !matches!(request, PushRegistrationHandoffRequestBody::Revoked { .. })
            || row.source_station_id != *issuer
            || request
                .request_digest()
                .map_err(PersistenceError::database)?
                .as_str()
                != row.request_digest
        {
            return Err(PersistenceError::SchemaViolation(
                "erasure found an unqualified Gateway revocation original".to_owned(),
            ));
        }
        let receipt: PushRegistrationInstallationReceipt =
            serde_json::from_value(row.receipt.clone()).map_err(PersistenceError::database)?;
        receipt
            .validate_for_handoff(
                &request,
                &row.source_station_id,
                &row.destination_gateway_id,
            )
            .map_err(PersistenceError::database)?;
        sql_query("INSERT INTO account_erasure_push_receipts(account_id,triggering_status_record_id,registration_id,receipt) VALUES($1,$2,$3,$4)")
            .bind::<Jsonb,_>(&account_json).bind::<Text,_>(record.as_str()).bind::<Text,_>(receipt.registration_id.as_str()).bind::<Jsonb,_>(row.receipt)
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    }
    Ok(())
}

fn validate_completed_package(
    package: &ErasureReceiptPackage,
    account: &AccountId,
    record: &arkret_wire::AccountStatusRecordId,
    issuer: &arkret_wire::DidCoreId,
    completed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    package
        .validate_bindings()
        .map_err(PersistenceError::database)?;
    let receipt = &package.receipt;
    let classes = [
        ErasedClass::AccountPrivateState,
        ErasedClass::PushRoutes,
        ErasedClass::DeviceSecrets,
        ErasedClass::ProjectionRows,
    ];
    if receipt.issuer_id != *issuer
        || receipt.trigger
            != (ErasureTrigger::AccountStatusRecord {
                account_status_record_id: record.clone(),
            })
        || receipt.subject.kind != ErasureSubjectKind::Principal
        || receipt.subject.subject_ref != account.principal_id.as_str()
        || receipt.scope.storage_boundary != ErasureStorageBoundary::AccountPrivateStore
        || receipt.scope.realm_id.is_some()
        || receipt.scope.retention_policy_id.is_some()
        || receipt.scope.target_refs.as_deref()
            != Some([account.principal_id.to_string()].as_slice())
        || receipt.outcome != ErasureAttemptOutcome::Completed
        || receipt.legal_hold_ref.is_some()
        || receipt.completed_at != completed_at
        || receipt.erased_classes.len() != classes.len()
        || !classes
            .iter()
            .all(|class| receipt.erased_classes.contains(class))
    {
        return Err(PersistenceError::SchemaViolation(
            "native private erasure issuer changed its exact completed boundary".to_owned(),
        ));
    }
    Ok(())
}

// These are exact private ownership predicates, never principal substrings.
// Canonical PCR/Event/Commit and historical public signer evidence are separate
// retained authority boundaries. Shared deployment clocks are not reset.
const ACTOR_PURGES: &[&str] = &[
    "DELETE FROM account_datas WHERE actor_id=$1",
    "DELETE FROM account_data_changes WHERE actor_id=$1",
    "DELETE FROM account_data_change_retention WHERE actor_id=$1",
    "DELETE FROM key_backups WHERE actor_id=$1",
    "DELETE FROM key_backup_list_revisions WHERE actor_id=$1",
    "DELETE FROM idempotency_keys WHERE actor_key=$1",
    "DELETE FROM notifications WHERE recipient_actor_id=$1",
    "DELETE FROM account_summary_versions WHERE actor_key=$1",
    "DELETE FROM account_summary_current WHERE actor_key=$1",
    "DELETE FROM account_global_versions WHERE actor_key=$1",
    "DELETE FROM account_global_channel_clocks WHERE actor_key=$1",
];

const ACCOUNT_KEY_PURGES: &[&str] = &[
    "DELETE FROM agent_draft_pending_intents WHERE controller_account_key=$1",
    "DELETE FROM agent_action_rejections WHERE controller_account_key=$1",
    "DELETE FROM agent_action_requests WHERE controller_account_key=$1",
    "DELETE FROM read_cursor_winners WHERE account_key=$1",
    "DELETE FROM device_push_routes WHERE account_key=$1",
    "DELETE FROM key_backup_unlock_entries e USING key_backup_unlock_authorities a WHERE e.authority_id=a.authority_id AND a.account_id=$1",
    "DELETE FROM key_backup_unlock_authorities WHERE account_id=$1",
    "DELETE FROM mimi_consent_decision_attempts d USING mimi_consent_correlations c WHERE d.consent_id=c.consent_id AND c.holder_account_id=$1",
    "DELETE FROM mimi_consent_correlations WHERE holder_account_id=$1",
    "DELETE FROM sync_cursor_handles WHERE binding_subject=$1",
    "DELETE FROM realm_state_snapshot_window_reservations WHERE account_id=$1",
    "DELETE FROM realm_state_snapshot_issuances WHERE account_id=$1",
];

const ACCOUNT_PURGES: &[&str] = &[
    "DELETE FROM actor_private_events WHERE owner_account_id=$1",
    "DELETE FROM consent_private_effect_jobs WHERE holder_account_id=$1",
    "DELETE FROM consent_private_effect_fences WHERE holder_account_id=$1",
    "DELETE FROM consent_private_proxy_fences WHERE holder_account_id=$1",
    "DELETE FROM consent_private_proxy_cuts WHERE holder_account_id=$1",
    "DELETE FROM consent_private_effect_cuts WHERE holder_account_id=$1",
    "DELETE FROM consent_current_states WHERE holder_account_id=$1",
    "DELETE FROM push_devices WHERE payload->'account_id'=$1",
    "DELETE FROM push_registration_handoff_intents WHERE local_account_id=$1",
    "DELETE FROM push_hard_logout_journal WHERE account_id=$1 AND completed_at IS NOT NULL",
];

const ACCOUNT_PK_PURGES: &[&str] = &[
    "DELETE FROM notifications WHERE controller_account_pk=$1",
    "DELETE FROM sessions WHERE account_pk=$1",
    "DELETE FROM invite_receive_policies WHERE account_pk=$1",
    "DELETE FROM invite_new_source_ledgers WHERE account_pk=$1",
    "DELETE FROM invite_new_source_hmac_keys WHERE account_pk=$1",
];

const NATIVE_ACCOUNT_PURGES: &[&str] = &[
    // Public device gate intent/results and sequence heads retain their exact
    // replay contract; neither contains a session grant or private key.
    "DELETE FROM key_backup_delete_challenges WHERE principal_id=$1 AND station_id=$2",
    "DELETE FROM recovery_sessions WHERE principal_id=$1 AND station_id=$2",
    "DELETE FROM security_transactions WHERE principal_id=$1 AND station_id=$2",
    "DELETE FROM device_message_ack_tokens WHERE recipient_device_authorization->>'principal_id'=$1 AND recipient_device_authorization->>'station_id'=$2",
    "DELETE FROM device_messages WHERE recipient_device_authorization->>'principal_id'=$1 AND recipient_device_authorization->>'station_id'=$2",
    "DELETE FROM mls_welcome_deliveries WHERE recipient_device_authorization->>'principal_id'=$1 AND recipient_device_authorization->>'station_id'=$2",
    "DELETE FROM device_keys WHERE device_authorization->>'principal_id'=$1 AND device_authorization->>'station_id'=$2",
    "DELETE FROM one_time_keys WHERE device_authorization->>'principal_id'=$1 AND device_authorization->>'station_id'=$2",
    "DELETE FROM devices WHERE actor_id=$1 AND station_id=$2",
];

pub(crate) async fn erase_private_state(
    pool: &PgPool,
    account: &AccountId,
    record_id: &arkret_wire::AccountStatusRecordId,
    issuer: &dyn AccountPrivateErasureReceiptIssuer,
) -> PersistenceResult<ErasureReceiptPackage> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_,PgTransactionError,_>(async move |conn| {
        crate::sync_cursor::retention::lock(conn, false).await?;
        // Only erasers serialize on this advisory key. Ordinary writers take
        // compatible Account row SHARE locks before their private row locks.
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended('account-private-erasure:'||$1::jsonb::text,0))")
            .bind::<Jsonb,_>(serde_json::to_value(account).map_err(PersistenceError::database)?).execute(&mut *conn).await?;
        let account_json=serde_json::to_value(account).map_err(PersistenceError::database)?;
        if let Some(original)=sql_query("SELECT triggering_status_record_id,package FROM account_private_erasure_completions WHERE account_id=$1")
            .bind::<Jsonb,_>(&account_json).get_result::<CompletionOriginal>(&mut *conn).await.optional()? {
            if original.triggering_status_record_id!=record_id.as_str() {
                return Err(PersistenceError::Conflict("duplicate_conflict: erased Account is bound to another terminal record".to_owned()).into());
            }
            let package:ErasureReceiptPackage=serde_json::from_value(original.package).map_err(PersistenceError::database)?;
            validate_completed_package(&package,account,record_id,&issuer.issuer_id(),package.receipt.completed_at)?;
            return Ok(package);
        }
        let accepted=sql_query("SELECT record FROM account_status_replica_records WHERE record_id=$1 AND account_id=$2")
            .bind::<Text,_>(record_id.as_str()).bind::<Jsonb,_>(&account_json)
            .get_result::<AcceptedStatus>(&mut *conn).await.optional()?
            .ok_or_else(||PersistenceError::Conflict("failed_precondition: exact accepted erasure record is unavailable".to_owned()))?;
        let status:AccountStatusRecord=serde_json::from_value(accepted.record).map_err(PersistenceError::database)?;
        status.validate_shape().map_err(PersistenceError::database)?;
        if status.account_id!=*account || status.account_status_record_id!=*record_id || status.status!=AccountStatus::ErasurePending {
            return Err(PersistenceError::Conflict("failed_precondition: record does not authorize exact Account erasure".to_owned()).into());
        }
        let owned=sql_query("SELECT pk FROM accounts WHERE principal_id=$1 AND station_id=$2 FOR UPDATE")
            .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
            .get_result::<OwnedAccount>(&mut *conn).await.optional()?
            .ok_or_else(||PersistenceError::NotFound("Account-private boundary is not owned here".to_owned()))?;
        let unresolved=sql_query("SELECT EXISTS(SELECT 1 FROM push_registration_handoff_intents WHERE local_account_id=$1 AND (desired_state<>'revoked' OR status<>'receipt_verified')) AS writable")
            .bind::<Jsonb,_>(&account_json).get_result::<PrivateWriteDecision>(&mut *conn).await?;
        if unresolved.writable {
            return Err(PersistenceError::Conflict("temporarily_unavailable: native Gateway revocation has no verified completion".to_owned()).into());
        }
        // Product policy_documents only accepts wildcard/Realm scope and is
        // not an Account legal-hold authority. Canonical policy/audit facts and
        // Blob legal holds belong to their independently declared boundaries.
        retain_verified_gateway_revocations(conn,account,record_id,&issuer.issuer_id()).await?;
        sql_query("SELECT set_config('arkret.account_private_erasure_record_id',$1,true)")
            .bind::<Text,_>(record_id.as_str()).execute(&mut *conn).await?;
        // Only the controller's pending private workflow belongs to this
        // Account. The Agent's own accepted identity, keys and inbox do not.
        sql_query("UPDATE agent_principals SET pairing_request_id=NULL,pending_pairing_commit_intent=NULL,pairing_code=NULL,pairing_expires_at=NULL,approval_request_id=NULL,recipient_id=NULL,runtime_key_binding_digest=NULL,approval_notification_id=NULL,runtime_key_material=NULL,approval_requested_at=NULL,updated_at=clock_timestamp() WHERE controller_account_pk=$1")
            .bind::<BigInt,_>(owned.pk).execute(&mut *conn).await?;
        // Freeze handle release before removing the only original mapping.
        sql_query("INSERT INTO handle_releases(localpart,released_at) SELECT localpart,clock_timestamp() FROM account_localparts WHERE account_pk=$1 ON CONFLICT(localpart) DO UPDATE SET released_at=EXCLUDED.released_at")
            .bind::<BigInt,_>(owned.pk).execute(&mut *conn).await?;
        sql_query("DELETE FROM account_localparts WHERE account_pk=$1").bind::<BigInt,_>(owned.pk).execute(&mut *conn).await?;
        // Version rows have no holder column; the exact accepted trigger binds
        // the actual inception PCR, including an independently hosted Org PCR.
        sql_query("DELETE FROM consent_result_versions v USING realm_commits c WHERE v.commit_id=c.commit_id AND c.realm_id=$1")
            .bind::<Text,_>(status.principal_control_realm_id.as_str()).execute(&mut *conn).await?;
        for statement in ACCOUNT_KEY_PURGES { sql_query(*statement).bind::<Text,_>(account.to_string()).execute(&mut *conn).await?; }
        for statement in ACCOUNT_PURGES { sql_query(*statement).bind::<Jsonb,_>(&account_json).execute(&mut *conn).await?; }
        for statement in NATIVE_ACCOUNT_PURGES { sql_query(*statement).bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str()).execute(&mut *conn).await?; }
        for statement in ACCOUNT_PK_PURGES { sql_query(*statement).bind::<BigInt,_>(owned.pk).execute(&mut *conn).await?; }
        // Source-table triggers can publish withdrawals. Remove their retained
        // account-sync copies last, after every source payload is gone.
        for statement in ACTOR_PURGES { sql_query(*statement).bind::<Text,_>(arkret_wire::ActorId::account(account.clone()).to_string()).execute(&mut *conn).await?; }
        sql_query("UPDATE accounts SET display_name='[user erased]',payload='{}'::jsonb,disabled_at=COALESCE(disabled_at,clock_timestamp()),updated_at=clock_timestamp() WHERE pk=$1")
            .bind::<BigInt,_>(owned.pk).execute(&mut *conn).await?;
        let completed=sql_query("SELECT date_trunc('milliseconds',clock_timestamp()) AS completed_at")
            .get_result::<CompletionTime>(&mut *conn).await?.completed_at;
        let package=issuer.issue_completed(completed)?;
        validate_completed_package(&package,account,record_id,&issuer.issuer_id(),completed)?;
        sql_query("INSERT INTO account_private_erasure_completions(account_id,triggering_status_record_id,package,completed_at) VALUES($1,$2,$3,$4)")
            .bind::<Jsonb,_>(&account_json).bind::<Text,_>(record_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&package).map_err(PersistenceError::database)?).bind::<Timestamptz,_>(completed)
            .execute(&mut *conn).await?;
        Ok(package)
    }).await.map_err(PgTransactionError::into_persistence)
}
