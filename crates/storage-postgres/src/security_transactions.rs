use arkret_models_crypto::{SecurityTransaction, SecurityTransactionKind, SecurityTransactionStep};
use arkret_wire::{DeviceId, DidCoreId, Hash, TransactionId};

use super::{
    AsyncConnection, AsyncPgConnection, BackupSeriesEraseProgressRecord, Binary, Jsonb, Nullable,
    OptionalExtension, PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    QueryableByName, RecoveryUnitCommitWrite, RevokeCommandTerminalWrite,
    RevokeProposalCommitWrite, RotationLocalCommitWrite, RotationPointerSwitchWrite,
    RotationUploadCommitWrite, RunQueryDsl, SecurityTransactionRecord,
    SecurityTransactionStepAttemptRecord, SecurityTransactionStepOutcomeRecord,
    SecurityTransactionStore, Text, Timestamptz, Uuid, Value, async_trait, ids, pg_conn, sql_query,
    sql_types,
};

mod recovery_unit;
mod revoke_unit;
mod rotation_units;

pub(crate) use rotation_units::refuse_rotation_reserved_pointer_in_connection;

pub struct PgSecurityTransactionStore {
    pub pool: PgPool,
}

#[cfg(feature = "test-support")]
impl PgSecurityTransactionStore {
    /// Install a structurally complete worker checkpoint for a crash/restart
    /// integration test. Production callers must advance through the guarded
    /// units instead; this hook exists because no public operation stops
    /// exactly between pointer switch and the erase worker.
    pub async fn seed_worker_checkpoint_for_test(
        &self,
        record: &SecurityTransactionRecord,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        insert_one(&mut conn, record).await
    }
}

#[derive(QueryableByName)]
struct SecurityTransactionRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Text)]
    principal_id: DidCoreId,
    #[diesel(sql_type = Text)]
    station_id: DidCoreId,
    #[diesel(sql_type = Nullable<Text>)]
    authorizing_device_id: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Jsonb)]
    prepared_plan: Value,
    #[diesel(sql_type = Text)]
    prepared_plan_digest: String,
    #[diesel(sql_type = Jsonb)]
    accepted_steps: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    revoke_proposal: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    revoke_command_outcome: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    terminal_outcome: Option<Value>,
    #[diesel(sql_type = Binary)]
    canonical_request: Vec<u8>,
}

#[derive(QueryableByName)]
struct SecurityTransactionStepOutcomeRow {
    #[diesel(sql_type = sql_types::Uuid)]
    transaction_id: Uuid,
    #[diesel(sql_type = Text)]
    step: String,
    #[diesel(sql_type = Binary)]
    canonical_request: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    response: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    participant_outcome: Option<Value>,
}

#[derive(QueryableByName)]
struct SecurityTransactionStepAttemptRow {
    #[diesel(sql_type = sql_types::Uuid)]
    transaction_id: Uuid,
    #[diesel(sql_type = Text)]
    step: String,
    #[diesel(sql_type = Binary)]
    canonical_request: Vec<u8>,
}

#[derive(QueryableByName)]
struct BackupSeriesEraseProgressRow {
    #[diesel(sql_type = sql_types::Uuid)]
    transaction_id: Uuid,
    #[diesel(sql_type = Binary)]
    canonical_request: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    outcome: Value,
}

impl TryFrom<SecurityTransactionStepAttemptRow> for SecurityTransactionStepAttemptRecord {
    type Error = PersistenceError;

    fn try_from(row: SecurityTransactionStepAttemptRow) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: ids::format_typed_uuid("transaction", &row.transaction_id),
            step: parse_stored("step attempt step", Value::String(row.step))?,
            canonical_request: row.canonical_request,
        })
    }
}

impl TryFrom<SecurityTransactionStepOutcomeRow> for SecurityTransactionStepOutcomeRecord {
    type Error = PersistenceError;

    fn try_from(row: SecurityTransactionStepOutcomeRow) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: ids::format_typed_uuid("transaction", &row.transaction_id),
            step: parse_stored("step outcome step", Value::String(row.step))?,
            canonical_request: row.canonical_request,
            response: row.response,
            participant_outcome: row.participant_outcome,
        })
    }
}

impl TryFrom<BackupSeriesEraseProgressRow> for BackupSeriesEraseProgressRecord {
    type Error = PersistenceError;

    fn try_from(row: BackupSeriesEraseProgressRow) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: ids::format_typed_uuid("transaction", &row.transaction_id),
            canonical_request: row.canonical_request,
            outcome: parse_stored("backup erase progress outcome", row.outcome)?,
        })
    }
}

impl TryFrom<SecurityTransactionRow> for SecurityTransactionRecord {
    type Error = PersistenceError;

    fn try_from(row: SecurityTransactionRow) -> Result<Self, Self::Error> {
        let resource = SecurityTransaction {
            transaction_id: TransactionId::new(ids::format_typed_uuid("transaction", &row.id))
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            kind: parse_stored("kind", Value::String(row.kind))?,
            account_id: arkret_wire::AccountId::new(row.principal_id, row.station_id),
            authorizing_device_id: row
                .authorizing_device_id
                .map(DeviceId::new)
                .transpose()
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            expires_at: row.expires_at,
            created_at: row.created_at,
            request_digest: Hash::new(row.request_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            prepared_plan: parse_stored("prepared_plan", row.prepared_plan)?,
            prepared_plan_digest: Hash::new(row.prepared_plan_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            accepted_steps: parse_stored("accepted_steps", row.accepted_steps)?,
            revoke_proposal: row
                .revoke_proposal
                .map(|value| parse_stored("revoke_proposal", value))
                .transpose()?,
            revoke_command_outcome: row
                .revoke_command_outcome
                .map(|value| parse_stored("revoke_command_outcome", value))
                .transpose()?,
            terminal_outcome: row
                .terminal_outcome
                .map(|result| parse_stored("terminal_outcome", result))
                .transpose()?,
        };
        resource
            .validate_structural()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        Ok(Self {
            canonical_request: row.canonical_request,
            resource,
        })
    }
}

fn parse_stored<T: serde::de::DeserializeOwned>(name: &str, value: Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(|error| {
        PersistenceError::Internal(format!(
            "stored security transaction {name} is invalid: {error}"
        ))
    })
}

const COLUMNS: &str = "id, kind, principal_id, station_id, authorizing_device_id, expires_at, created_at, \
    request_digest, prepared_plan, prepared_plan_digest, accepted_steps, \
    revoke_proposal, revoke_command_outcome, terminal_outcome, canonical_request";

pub(crate) async fn load_one(
    conn: &mut AsyncPgConnection,
    transaction_id: &str,
    for_update: bool,
) -> PersistenceResult<Option<SecurityTransactionRecord>> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    let transaction_uuid =
        ids::parse_typed_uuid(transaction_id, "transaction").ok_or_else(|| {
            PersistenceError::SchemaViolation(format!(
                "malformed transaction_id `{transaction_id}`"
            ))
        })?;
    sql_query(format!(
        "SELECT {COLUMNS} FROM security_transactions WHERE id = $1{lock}"
    ))
    .bind::<sql_types::Uuid, _>(transaction_uuid)
    .get_result::<SecurityTransactionRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(SecurityTransactionRecord::try_from)
    .transpose()
}

async fn load_backup_erase_progress(
    conn: &mut AsyncPgConnection,
    transaction_id: &str,
    for_update: bool,
) -> PersistenceResult<Option<BackupSeriesEraseProgressRecord>> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    let transaction_uuid =
        ids::parse_typed_uuid(transaction_id, "transaction").ok_or_else(|| {
            PersistenceError::SchemaViolation(format!(
                "malformed transaction_id `{transaction_id}`"
            ))
        })?;
    sql_query(format!(
        "SELECT transaction_id, canonical_request, outcome \
         FROM security_transaction_backup_erase_progress \
         WHERE transaction_id = $1{lock}"
    ))
    .bind::<sql_types::Uuid, _>(transaction_uuid)
    .get_result::<BackupSeriesEraseProgressRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(BackupSeriesEraseProgressRecord::try_from)
    .transpose()
}

async fn insert_one(
    conn: &mut AsyncPgConnection,
    record: &SecurityTransactionRecord,
) -> PersistenceResult<()> {
    let resource = &record.resource;
    sql_query(
        "INSERT INTO security_transactions \
         (id, kind, principal_id, station_id, authorizing_device_id, expires_at, created_at, request_digest, \
           prepared_plan, prepared_plan_digest, accepted_steps, \
           revoke_proposal, revoke_command_outcome, terminal_outcome, canonical_request) \
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(
        resource.transaction_id.as_str(),
    ))
    .bind::<Text, _>(match resource.kind {
        SecurityTransactionKind::Recovery => "recovery",
        SecurityTransactionKind::SecurityRotation => "security_rotation",
    })
    .bind::<Text, _>(resource.account_id.principal_id.as_str())
    .bind::<Text, _>(resource.account_id.station_id.as_str())
    .bind::<Nullable<Text>, _>(
        resource
            .authorizing_device_id
            .as_ref()
            .map(|device_id| device_id.as_str()),
    )
    .bind::<Timestamptz, _>(resource.expires_at)
    .bind::<Timestamptz, _>(resource.created_at)
    .bind::<Text, _>(resource.request_digest.as_str())
    .bind::<Jsonb, _>(
        serde_json::to_value(&resource.prepared_plan)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Text, _>(resource.prepared_plan_digest.as_str())
    .bind::<Jsonb, _>(
        serde_json::to_value(&resource.accepted_steps)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Nullable<Jsonb>, _>(
        resource
            .revoke_proposal
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Nullable<Jsonb>, _>(
        resource
            .revoke_command_outcome
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Nullable<Jsonb>, _>(
        resource
            .terminal_outcome
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Binary, _>(&record.canonical_request)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(PersistenceError::database)
}

pub(crate) async fn load_step_outcome(
    conn: &mut AsyncPgConnection,
    transaction_id: &str,
    step: SecurityTransactionStep,
) -> PersistenceResult<Option<SecurityTransactionStepOutcomeRecord>> {
    let transaction_uuid =
        ids::parse_typed_uuid(transaction_id, "transaction").ok_or_else(|| {
            PersistenceError::SchemaViolation(format!(
                "malformed transaction_id `{transaction_id}`"
            ))
        })?;
    sql_query(
        "SELECT transaction_id, step, canonical_request, response, participant_outcome \
         FROM security_transaction_step_outcomes WHERE transaction_id = $1 AND step = $2",
    )
    .bind::<sql_types::Uuid, _>(transaction_uuid)
    .bind::<Text, _>(enum_text(step)?)
    .get_result::<SecurityTransactionStepOutcomeRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(SecurityTransactionStepOutcomeRecord::try_from)
    .transpose()
}

async fn load_step_attempt(
    conn: &mut AsyncPgConnection,
    transaction_id: &str,
    step: SecurityTransactionStep,
) -> PersistenceResult<Option<SecurityTransactionStepAttemptRecord>> {
    let transaction_uuid =
        ids::parse_typed_uuid(transaction_id, "transaction").ok_or_else(|| {
            PersistenceError::SchemaViolation(format!(
                "malformed transaction_id `{transaction_id}`"
            ))
        })?;
    sql_query(
        "SELECT transaction_id, step, canonical_request \
         FROM security_transaction_step_attempts WHERE transaction_id = $1 AND step = $2",
    )
    .bind::<sql_types::Uuid, _>(transaction_uuid)
    .bind::<Text, _>(enum_text(step)?)
    .get_result::<SecurityTransactionStepAttemptRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(SecurityTransactionStepAttemptRecord::try_from)
    .transpose()
}

async fn update_mutable_fields(
    conn: &mut AsyncPgConnection,
    record: &SecurityTransactionRecord,
) -> PersistenceResult<()> {
    sql_query(
        "UPDATE security_transactions SET accepted_steps = $2, \
         revoke_proposal = $3, revoke_command_outcome = $4, \
         terminal_outcome = $5 WHERE id = $1",
    )
    .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(
        record.resource.transaction_id.as_str(),
    ))
    .bind::<Jsonb, _>(
        serde_json::to_value(&record.resource.accepted_steps)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Nullable<Jsonb>, _>(
        record
            .resource
            .revoke_proposal
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Nullable<Jsonb>, _>(
        record
            .resource
            .revoke_command_outcome
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Nullable<Jsonb>, _>(
        record
            .resource
            .terminal_outcome
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(PersistenceError::database)
}

fn enum_text<T: serde::Serialize>(value: T) -> PersistenceResult<String> {
    serde_json::to_value(value)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| PersistenceError::Internal("wire enum did not serialize as text".to_owned()))
}

#[derive(QueryableByName)]
struct RecoverySessionBindingRow {
    #[diesel(sql_type = Text)]
    principal_id: DidCoreId,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<sql_types::Uuid>)]
    transaction_id: Option<Uuid>,
}

async fn lock_transaction_recovery_authority(
    conn: &mut AsyncPgConnection,
    record: &SecurityTransactionRecord,
) -> Result<(), PgTransactionError> {
    if record.resource.terminal_outcome.is_some() {
        return Ok(());
    }
    if let Some(binding) = record.resource.recovery_plan().map(|plan| &plan.binding) {
        let session = crate::recovery::lock_recovery_session_authority(
            conn,
            binding.recovery_session_id.as_str(),
        )
        .await?;
        if session["principal_id"].as_str()
            != Some(record.resource.account_id.principal_id.as_str())
            || session["station_id"].as_str()
                != Some(record.resource.account_id.station_id.as_str())
        {
            return Err(PersistenceError::Conflict(
                "recovery transaction account mismatch".to_owned(),
            )
            .into());
        }
    }
    Ok(())
}

/// Where the durable step attempt for an accepted step comes from.
///
/// Steps a coordinator drives on its own still freeze their canonical request
/// bytes before the participant side effect, so their attempt row must already
/// exist. `security-transactions.md` sections 2.2 and 2.5 forbid that shape for
/// `commit_recovery_unit`: a failed re-verification MUST NOT freeze any step
/// outcome and a corrected receipt MUST still be accepted, so its attempt row
/// is written in the same transaction as the outcome it belongs to and
/// disappears with it on rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StepAttemptSource {
    DurablyBegun,
    CoCommittedWithOutcome,
}

/// Accept one security-transaction step inside a transaction the caller owns.
///
/// This is the whole terminal ledger write: the first response bytes, the
/// mutable resource fields and, for a completed recovery transaction, the
/// recovery session consumption.
pub(crate) async fn accept_step_in_transaction(
    conn: &mut AsyncPgConnection,
    record: SecurityTransactionRecord,
    outcome: SecurityTransactionStepOutcomeRecord,
    attempt_source: StepAttemptSource,
) -> Result<SecurityTransactionStepOutcomeRecord, PgTransactionError> {
    record
        .resource
        .validate_structural()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let transaction_id = record.resource.transaction_id.as_str().to_owned();
    if outcome.transaction_id != transaction_id {
        return Err(PersistenceError::SchemaViolation(
            "security transaction step outcome belongs to a different transaction".to_owned(),
        )
        .into());
    }
    if let Some(existing) = load_one(conn, &transaction_id, false).await? {
        lock_transaction_recovery_authority(conn, &existing).await?;
    }
    let existing = load_one(conn, &transaction_id, true)
        .await?
        .ok_or_else(|| {
            PersistenceError::NotFound(format!("transaction_id `{transaction_id}` not found"))
        })?;
    let stored_outcome = load_step_outcome(conn, &transaction_id, outcome.step).await?;
    match super::classify_security_transaction_first_write(
        stored_outcome
            .as_ref()
            .map(|stored| stored.canonical_request.as_slice()),
        &outcome.canonical_request,
    )? {
        super::SecurityTransactionFirstWriteDecision::ExactRetry => {
            return Ok(stored_outcome.expect("exact retry has an existing outcome"));
        }
        super::SecurityTransactionFirstWriteDecision::Insert => {}
    }
    if attempt_source == StepAttemptSource::CoCommittedWithOutcome {
        insert_step_attempt(conn, &transaction_id, &outcome).await?;
    }
    let attempt = load_step_attempt(conn, &transaction_id, outcome.step)
        .await?
        .ok_or_else(|| {
            PersistenceError::Conflict(format!(
                "security transaction step {:?} was not durably begun",
                outcome.step
            ))
        })?;
    super::validate_security_transaction_step_accept(&existing, &record, &attempt, &outcome)?;
    sql_query(
        "INSERT INTO security_transaction_step_outcomes \
         (transaction_id, step, canonical_request, response, participant_outcome) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(&transaction_id))
    .bind::<Text, _>(enum_text(outcome.step)?)
    .bind::<Binary, _>(&outcome.canonical_request)
    .bind::<Jsonb, _>(&outcome.response)
    .bind::<Nullable<Jsonb>, _>(&outcome.participant_outcome)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    update_mutable_fields(conn, &record).await?;
    if matches!(
        record.resource.terminal_outcome,
        Some(arkret_models_crypto::SecurityTransactionTerminalOutcome::Completed { .. })
    ) && let Some(binding) = record.resource.recovery_plan().map(|plan| &plan.binding)
    {
        let affected = sql_query(
            "UPDATE recovery_sessions SET state = 'completed', updated_at = NOW() \
             WHERE id = $1 AND transaction_id = $2 AND state = 'verified'",
        )
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(
            binding.recovery_session_id.as_str(),
        ))
        .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(&transaction_id))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if affected != 1 {
            return Err(PersistenceError::Conflict(
                "terminal recovery transaction does not own a verified recovery session".to_owned(),
            )
            .into());
        }
    }
    Ok(outcome)
}

/// Freeze the canonical request bytes of a step whose attempt row commits with
/// its outcome. An exact retry re-presents the same bytes, so the insert is a
/// no-op; different bytes for an already accepted step are refused by the
/// outcome classification above before this is reached.
async fn insert_step_attempt(
    conn: &mut AsyncPgConnection,
    transaction_id: &str,
    outcome: &SecurityTransactionStepOutcomeRecord,
) -> Result<(), PgTransactionError> {
    let existing = load_step_attempt(conn, transaction_id, outcome.step).await?;
    match super::classify_security_transaction_first_write(
        existing
            .as_ref()
            .map(|stored| stored.canonical_request.as_slice()),
        &outcome.canonical_request,
    )? {
        super::SecurityTransactionFirstWriteDecision::ExactRetry => return Ok(()),
        super::SecurityTransactionFirstWriteDecision::Insert => {}
    }
    sql_query(
        "INSERT INTO security_transaction_step_attempts \
         (transaction_id, step, canonical_request) VALUES ($1, $2, $3)",
    )
    .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(transaction_id))
    .bind::<Text, _>(enum_text(outcome.step)?)
    .bind::<Binary, _>(&outcome.canonical_request)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

#[async_trait]
impl SecurityTransactionStore for PgSecurityTransactionStore {
    async fn commit_revoke_command_terminal(
        &self,
        write: RevokeCommandTerminalWrite,
    ) -> PersistenceResult<SecurityTransactionRecord> {
        write.validate()?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            revoke_unit::commit_revoke_command_terminal_in_connection(conn, write).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn commit_revoke_proposal(
        &self,
        write: RevokeProposalCommitWrite,
    ) -> PersistenceResult<arkret_wire::RealmCommit> {
        write.validate()?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            revoke_unit::commit_revoke_proposal_in_connection(conn, write).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn commit_rotation_upload(
        &self,
        write: RotationUploadCommitWrite,
    ) -> PersistenceResult<SecurityTransactionRecord> {
        write.validate()?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            rotation_units::commit_rotation_upload_in_connection(conn, write).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn commit_rotation_pointer_switch(
        &self,
        write: RotationPointerSwitchWrite,
    ) -> PersistenceResult<SecurityTransactionRecord> {
        write.validate()?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            rotation_units::commit_rotation_pointer_switch_in_connection(conn, write).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn commit_rotation_local_commit(
        &self,
        write: RotationLocalCommitWrite,
    ) -> PersistenceResult<SecurityTransactionRecord> {
        write.validate()?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            rotation_units::commit_rotation_local_commit_in_connection(conn, write).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn rotations_awaiting_worker(&self, limit: u32) -> PersistenceResult<Vec<String>> {
        #[derive(QueryableByName)]
        struct AwaitingRow {
            #[diesel(sql_type = sql_types::Uuid)]
            id: Uuid,
        }
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT id FROM security_transactions WHERE kind='security_rotation' \
             AND terminal_outcome IS NULL AND jsonb_array_length(accepted_steps) < 4 \
             ORDER BY created_at, id LIMIT $1",
        )
        .bind::<sql_types::BigInt, _>(i64::from(limit))
        .load::<AwaitingRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(rows
            .into_iter()
            .map(|row| format!("ak:transaction:{}", row.id))
            .collect())
    }

    async fn commit_recovery_unit(
        &self,
        write: RecoveryUnitCommitWrite,
    ) -> PersistenceResult<SecurityTransactionStepOutcomeRecord> {
        write.validate()?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            recovery_unit::commit_recovery_unit_in_connection(conn, write).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn create(
        &self,
        record: SecurityTransactionRecord,
    ) -> PersistenceResult<SecurityTransactionRecord> {
        record
            .resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if record.resource.revoke_proposal.is_some()
            || record.resource.revoke_command_outcome.is_some()
        {
            return Err(PersistenceError::Conflict(
                "security rotation proposal and result require their guarded durable unit"
                    .to_owned(),
            ));
        }
        arkret_canonical::canonical::verify_digest(
            &record.canonical_request,
            record.resource.request_digest.as_str(),
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let recovery_session_id = record
            .resource
            .recovery_plan()
            .map(|plan| &plan.binding)
            .map(|binding| binding.recovery_session_id.as_str().to_owned());
        let transaction_id = record.resource.transaction_id.as_str().to_owned();
        let principal_id = record.resource.account_id.principal_id.clone();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            if let Some(existing)=load_one(conn,&transaction_id,false).await? {
                lock_transaction_recovery_authority(conn,&existing).await?;
            } else {
                lock_transaction_recovery_authority(conn,&record).await?;
            }
            let existing = load_one(conn, &transaction_id, true).await?;
            match super::classify_security_transaction_first_write(
                existing
                    .as_ref()
                    .map(|stored| stored.canonical_request.as_slice()),
                &record.canonical_request,
            )? {
                super::SecurityTransactionFirstWriteDecision::ExactRetry => {
                    return Ok(existing.expect("exact retry has an existing record"));
                }
                super::SecurityTransactionFirstWriteDecision::Insert => {}
            }
            if let Some(recovery_session_id) = &recovery_session_id {
                let session = sql_query(
                    "SELECT principal_id, state, expires_at, transaction_id FROM recovery_sessions \
                     WHERE id = $1 FOR UPDATE",
                )
                .bind::<sql_types::Uuid, _>(
                    ids::parse_typed_uuid(recovery_session_id, "recovery_session").ok_or_else(
                        || {
                            PersistenceError::SchemaViolation(format!(
                                "malformed recovery_session_id `{recovery_session_id}`"
                            ))
                        },
                    )?,
                )
                .get_result::<RecoverySessionBindingRow>(conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?
                .ok_or_else(|| {
                    PersistenceError::NotFound(format!(
                        "recovery_session_id `{recovery_session_id}` not found"
                    ))
                })?;
                if session.principal_id != principal_id
                    || session.state != "verified"
                    || session.expires_at <= chrono::Utc::now()
                    || session.transaction_id.is_some()
                {
                    return Err(PersistenceError::Conflict(
                        "recovery session is not an unbound current verified session for the transaction principal"
                            .to_owned(),
                    )
                    .into());
                }
            }
            insert_one(conn, &record).await?;
            if let Some(recovery_session_id) = recovery_session_id {
                sql_query(
                    "UPDATE recovery_sessions SET transaction_id = $2, updated_at = NOW() \
                     WHERE id = $1 AND transaction_id IS NULL",
                )
                .bind::<sql_types::Uuid, _>(
                    ids::parse_typed_uuid(&recovery_session_id, "recovery_session").ok_or_else(
                        || {
                            PersistenceError::SchemaViolation(format!(
                                "malformed recovery_session_id `{recovery_session_id}`"
                            ))
                        },
                    )?,
                )
                .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(&transaction_id))
                .execute(conn)
                .await
                .map_err(PersistenceError::database)?;
            }
            Ok(record)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn get(
        &self,
        transaction_id: &str,
    ) -> PersistenceResult<Option<SecurityTransactionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_one(&mut conn, transaction_id, false).await
    }

    async fn update(&self, record: SecurityTransactionRecord) -> PersistenceResult<()> {
        record
            .resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let mut conn = pg_conn(&self.pool).await?;
        let transaction_id = record.resource.transaction_id.as_str().to_owned();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            if let Some(existing) = load_one(conn, &transaction_id, false).await? {
                lock_transaction_recovery_authority(conn, &existing).await?;
            }
            let existing = load_one(conn, &transaction_id, true)
                .await?
                .ok_or_else(|| {
                    PersistenceError::NotFound(format!(
                        "transaction_id `{transaction_id}` not found"
                    ))
                })?;
            super::validate_security_transaction_update(&existing, &record)?;
            if existing.resource.revoke_command_outcome != record.resource.revoke_command_outcome {
                return Err(PersistenceError::Conflict(
                    "revoke command result requires its guarded terminal unit".to_owned(),
                )
                .into());
            }
            if record.resource.accepted_steps != existing.resource.accepted_steps {
                return Err(PersistenceError::Conflict(
                    "security transaction accepted step requires its durable outcome unit"
                        .to_owned(),
                )
                .into());
            }
            update_mutable_fields(conn, &record).await?;
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn step_outcome(
        &self,
        transaction_id: &str,
        step: SecurityTransactionStep,
    ) -> PersistenceResult<Option<SecurityTransactionStepOutcomeRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_step_outcome(&mut conn, transaction_id, step).await
    }

    async fn step_attempt(
        &self,
        transaction_id: &str,
        step: SecurityTransactionStep,
    ) -> PersistenceResult<Option<SecurityTransactionStepAttemptRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_step_attempt(&mut conn, transaction_id, step).await
    }

    async fn begin_step(
        &self,
        attempt: SecurityTransactionStepAttemptRecord,
    ) -> PersistenceResult<SecurityTransactionStepAttemptRecord> {
        let transaction_id = attempt.transaction_id.clone();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            if let Some(record) = load_one(conn, &transaction_id, false).await? {
                lock_transaction_recovery_authority(conn, &record).await?;
            }
            if load_one(conn, &transaction_id, true).await?.is_none() {
                return Err(PersistenceError::NotFound(format!(
                    "transaction_id `{transaction_id}` not found"
                ))
                .into());
            }
            let existing = load_step_attempt(conn, &transaction_id, attempt.step).await?;
            match super::classify_security_transaction_first_write(
                existing
                    .as_ref()
                    .map(|stored| stored.canonical_request.as_slice()),
                &attempt.canonical_request,
            )? {
                super::SecurityTransactionFirstWriteDecision::ExactRetry => {
                    return Ok(existing.expect("exact retry has an existing attempt"));
                }
                super::SecurityTransactionFirstWriteDecision::Insert => {}
            }
            sql_query(
                "INSERT INTO security_transaction_step_attempts \
                 (transaction_id, step, canonical_request) VALUES ($1, $2, $3)",
            )
            .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(&transaction_id))
            .bind::<Text, _>(enum_text(attempt.step)?)
            .bind::<Binary, _>(&attempt.canonical_request)
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(attempt)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn accept_step(
        &self,
        record: SecurityTransactionRecord,
        outcome: SecurityTransactionStepOutcomeRecord,
    ) -> PersistenceResult<SecurityTransactionStepOutcomeRecord> {
        if matches!(
            outcome.step,
            SecurityTransactionStep::Revoke
                | SecurityTransactionStep::UploadNewMaterial
                | SecurityTransactionStep::SwitchAuthoritativePointer
                | SecurityTransactionStep::LocalCommit
        ) {
            return Err(PersistenceError::Conflict(format!(
                "rotation {:?} accepted step requires its guarded unit",
                outcome.step
            )));
        }
        record
            .resource
            .validate_structural()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let transaction_id = record.resource.transaction_id.as_str().to_owned();
        if outcome.transaction_id != transaction_id {
            return Err(PersistenceError::SchemaViolation(
                "security transaction step outcome belongs to a different transaction".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            accept_step_in_transaction(conn, record, outcome, StepAttemptSource::DurablyBegun).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn backup_erase_progress(
        &self,
        transaction_id: &str,
    ) -> PersistenceResult<Option<BackupSeriesEraseProgressRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_backup_erase_progress(&mut conn, transaction_id, false).await
    }

    async fn begin_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressRecord,
    ) -> PersistenceResult<BackupSeriesEraseProgressRecord> {
        super::validate_backup_erase_progress_initial(&progress)?;
        let transaction_id = progress.transaction_id.clone();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            if load_one(conn, &transaction_id, true).await?.is_none() {
                return Err(PersistenceError::NotFound(format!(
                    "transaction_id `{transaction_id}` not found"
                ))
                .into());
            }
            let existing = load_backup_erase_progress(conn, &transaction_id, true).await?;
            match super::classify_security_transaction_first_write(
                existing
                    .as_ref()
                    .map(|stored| stored.canonical_request.as_slice()),
                &progress.canonical_request,
            )? {
                super::SecurityTransactionFirstWriteDecision::ExactRetry => {
                    return Ok(existing.expect("exact retry has erase progress"));
                }
                super::SecurityTransactionFirstWriteDecision::Insert => {}
            }
            let outcome = serde_json::to_value(&progress.outcome)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            sql_query(
                "INSERT INTO security_transaction_backup_erase_progress \
                 (transaction_id, canonical_request, outcome) VALUES ($1, $2, $3)",
            )
            .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(&transaction_id))
            .bind::<Binary, _>(&progress.canonical_request)
            .bind::<Jsonb, _>(outcome)
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(progress)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn update_backup_erase(
        &self,
        progress: BackupSeriesEraseProgressRecord,
    ) -> PersistenceResult<BackupSeriesEraseProgressRecord> {
        let transaction_id = progress.transaction_id.clone();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let existing = load_backup_erase_progress(conn, &transaction_id, true)
                .await?
                .ok_or_else(|| {
                    PersistenceError::NotFound(format!(
                        "backup erase progress for transaction `{transaction_id}` not found"
                    ))
                })?;
            super::validate_backup_erase_progress_update(&existing, &progress)?;
            let outcome = serde_json::to_value(&progress.outcome)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            sql_query(
                "UPDATE security_transaction_backup_erase_progress \
                 SET outcome = $2, updated_at = NOW() WHERE transaction_id = $1",
            )
            .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(&transaction_id))
            .bind::<Jsonb, _>(outcome)
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(progress)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}
