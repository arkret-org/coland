use horme::RunQueryDsl as _;

use coland_storage::{
    AuthorityCommitWriteOutcome, PersistenceError, RecoveryUnitCommitWrite,
    SecurityTransactionRecord,
};

use super::{
    AsyncPgConnection, PgTransactionError, insert_one, load_one, lock_transaction_identity,
};
use crate::authority_commit::{
    commit_verified_pcr_device_transaction_in_connection, queue_event_in_connection,
};

/// The caller owns the PostgreSQL transaction. A failure in either Commit or
/// the terminal ledger rolls back the queued Events and every earlier write.
pub(super) async fn commit_recovery_unit_in_connection(
    conn: &mut AsyncPgConnection,
    write: RecoveryUnitCommitWrite,
) -> Result<SecurityTransactionRecord, PgTransactionError> {
    let transaction_id = write.transaction.resource.transaction_id().to_string();
    lock_transaction_identity(conn, &transaction_id).await?;
    if let Some(existing) = load_one(conn, &transaction_id, true).await? {
        super::super::classify_security_transaction_first_write(
            Some(&existing.canonical_request),
            &write.transaction.canonical_request,
        )?;
        // A committed first outcome wins even if this attempt signed a later C.
        // Replays do not re-consume the Session or rerun current admission.
        existing.recovery()?;
        return Ok(existing);
    }
    write.validate()?;
    let receipt = &write.transaction.recovery()?.recovery_receipt;
    crate::recovery::lock_recovery_session_authority(conn, receipt.recovery_session_id.as_str())
        .await?;
    let locked_session =
        crate::recovery::load_session_in_connection(conn, receipt.recovery_session_id.as_str())
            .await?
            .ok_or_else(|| {
                PersistenceError::Conflict("verified Recovery Session disappeared".into())
            })?;
    if locked_session != write.verified_session {
        return Err(PersistenceError::Conflict(
            "verified Recovery Session basis changed before admission".into(),
        )
        .into());
    }
    // This final row is invisible until both actual Commits and consumption
    // succeed. Its FK is needed by the co-transaction native recovery episode.
    insert_one(conn, &write.transaction).await?;
    super::replacement_freshness::require_fresh(conn, &write).await?;
    for commit in &write.commits {
        queue_event_in_connection(conn, &commit.event, write.queued_at).await?;
        match commit_verified_pcr_device_transaction_in_connection(conn, commit).await? {
            AuthorityCommitWriteOutcome::Committed => {}
            AuthorityCommitWriteOutcome::Duplicate => {
                return Err(PersistenceError::Conflict(
                    "recovery Event was committed outside this terminal unit".to_owned(),
                )
                .into());
            }
            AuthorityCommitWriteOutcome::StaleAuthority(_) => {
                return Err(PersistenceError::Conflict(
                    "PCR authority changed before recovery terminal commit".to_owned(),
                )
                .into());
            }
        }
        crate::pcr_device_current_states::project_pcr_device_current_in_connection(
            conn,
            &commit.event,
            &commit.commit,
            None,
        )
        .await?;
    }
    crate::agent_producer_signer_keys::retain_recovery_unit_in_connection(conn, &write).await?;
    super::content_recovery_preparation::retain_in_connection(conn, &write).await?;
    let affected = super::sql_query("UPDATE recovery_sessions SET state='completed',transaction_id=$2,updated_at=$3 WHERE id=$1 AND state='verified' AND transaction_id IS NULL AND expires_at>clock_timestamp() AND $4>clock_timestamp()")
        .bind::<super::sql_types::Uuid,_>(super::ids::typed_uuid_part_expect_internal(write.verified_session.recovery_session_id.as_str()))
        .bind::<super::sql_types::Uuid,_>(super::ids::typed_uuid_part_expect_internal(&transaction_id))
        .bind::<super::Timestamptz,_>(write.queued_at)
        .bind::<super::Timestamptz,_>(write.transaction.recovery()?.recovery_receipt.expires_at)
        .execute(conn).await.map_err(PersistenceError::database)?;
    if affected != 1 {
        return Err(PersistenceError::Conflict(
            "Recovery Session was consumed or expired before the atomic unit".into(),
        )
        .into());
    }
    Ok(write.transaction)
}
