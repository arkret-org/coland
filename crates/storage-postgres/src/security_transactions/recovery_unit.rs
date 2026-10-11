use coland_storage::{
    AuthorityCommitWriteOutcome, PersistenceError, RecoveryUnitCommitWrite,
    SecurityTransactionStepOutcomeRecord,
};

use super::{
    AsyncPgConnection, PgTransactionError, StepAttemptSource, accept_step_in_transaction, load_one,
    load_step_outcome, lock_transaction_recovery_authority,
};
use crate::authority_commit::{
    commit_verified_pcr_device_transaction_in_connection, queue_event_in_connection,
};

/// The caller owns the PostgreSQL transaction. A failure in either Commit or
/// the terminal ledger rolls back the queued Events and every earlier write.
pub(super) async fn commit_recovery_unit_in_connection(
    conn: &mut AsyncPgConnection,
    write: RecoveryUnitCommitWrite,
) -> Result<SecurityTransactionStepOutcomeRecord, PgTransactionError> {
    write.validate()?;
    let transaction_id = write.transaction.resource.transaction_id.as_str();
    if let Some(existing) = load_one(conn, transaction_id, false).await? {
        lock_transaction_recovery_authority(conn, &existing).await?;
    }
    let existing = load_one(conn, transaction_id, true).await?.ok_or_else(|| {
        PersistenceError::NotFound(format!("recovery transaction `{transaction_id}` not found"))
    })?;
    if let Some(outcome) = load_step_outcome(conn, transaction_id, write.step_outcome.step).await? {
        if outcome.canonical_request == write.step_outcome.canonical_request {
            return Ok(outcome);
        }
        return Err(PersistenceError::Conflict(
            "terminal recovery step canonical request changed".to_owned(),
        )
        .into());
    }
    if existing.resource != write.transaction.resource
        && existing.resource.terminal_outcome.is_some()
    {
        return Err(PersistenceError::Conflict(
            "recovery transaction already has a different terminal result".to_owned(),
        )
        .into());
    }
    if existing.resource.prepared_plan != write.transaction.resource.prepared_plan
        || existing.canonical_request != write.transaction.canonical_request
    {
        return Err(PersistenceError::Conflict(
            "recovery unit changed the prepared transaction".to_owned(),
        )
        .into());
    }
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
        crate::pcr_device_current_results::project_pcr_device_current_in_connection(
            conn,
            &commit.event,
            &commit.commit,
            None,
        )
        .await?;
    }
    accept_step_in_transaction(
        conn,
        write.transaction,
        write.step_outcome,
        StepAttemptSource::CoCommittedWithOutcome,
    )
    .await
}
