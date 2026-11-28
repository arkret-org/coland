use arkret_models_crypto::{
    SecurityRotationTransaction, SecurityTransaction, SecurityTransactionKind,
    SecurityTransactionStep,
};
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

mod content_recovery_preparation;
mod content_recovery_source;
mod recovery_census_cut;
mod recovery_inventory;
mod recovery_unit;
mod replacement_freshness;
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
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            Ok(insert_one(conn, record).await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
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
    #[diesel(sql_type = Nullable<Timestamptz>) ]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Text>) ]
    request_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>) ]
    prepared_plan: Option<Value>,
    #[diesel(sql_type = Nullable<Text>) ]
    prepared_plan_digest: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>) ]
    accepted_steps: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    revoke_proposal: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    revoke_command_outcome: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    terminal_outcome: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    recovery_completion: Option<Value>,
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
        let missing =
            |name: &str| PersistenceError::Internal(format!("stored Rotation missing {name}"));
        let transaction_id = TransactionId::new(ids::format_typed_uuid("transaction", &row.id))
            .map_err(|e| PersistenceError::Internal(e.to_string()))?;
        let account_id = arkret_wire::AccountId::new(row.principal_id, row.station_id);
        let resource = match row.kind.as_str() {
            "recovery" => {
                let completed: arkret_models_crypto::RecoveryTransactionCompletion = parse_stored(
                    "recovery_completion",
                    row.recovery_completion
                        .ok_or_else(|| missing("recovery_completion"))?,
                )?;
                if completed.transaction_id != transaction_id
                    || completed.account_id != account_id
                    || completed.created_at != row.created_at
                {
                    return Err(PersistenceError::Internal(
                        "stored Recovery identity differs from its immutable closure".into(),
                    ));
                }
                SecurityTransaction::Recovery(completed)
            }
            "security_rotation" => {
                SecurityTransaction::SecurityRotation(SecurityRotationTransaction {
                    transaction_id,
                    kind: SecurityTransactionKind::SecurityRotation,
                    account_id,
                    authorizing_device_id: DeviceId::new(
                        row.authorizing_device_id
                            .ok_or_else(|| missing("authorizing_device_id"))?,
                    )
                    .map_err(|e| PersistenceError::Internal(e.to_string()))?,
                    expires_at: row.expires_at.ok_or_else(|| missing("expires_at"))?,
                    created_at: row.created_at,
                    request_digest: Hash::new(
                        row.request_digest
                            .ok_or_else(|| missing("request_digest"))?,
                    )
                    .map_err(|e| PersistenceError::Internal(e.to_string()))?,
                    prepared_plan: parse_stored(
                        "prepared_plan",
                        row.prepared_plan.ok_or_else(|| missing("prepared_plan"))?,
                    )?,
                    prepared_plan_digest: Hash::new(
                        row.prepared_plan_digest
                            .ok_or_else(|| missing("prepared_plan_digest"))?,
                    )
                    .map_err(|e| PersistenceError::Internal(e.to_string()))?,
                    accepted_steps: parse_stored(
                        "accepted_steps",
                        row.accepted_steps
                            .ok_or_else(|| missing("accepted_steps"))?,
                    )?,
                    revoke_proposal: row
                        .revoke_proposal
                        .map(|v| parse_stored("revoke_proposal", v))
                        .transpose()?,
                    revoke_command_outcome: row
                        .revoke_command_outcome
                        .map(|v| parse_stored("revoke_command_outcome", v))
                        .transpose()?,
                    terminal_outcome: row
                        .terminal_outcome
                        .map(|v| parse_stored("terminal_outcome", v))
                        .transpose()?,
                })
            }
            _ => {
                return Err(PersistenceError::Internal(
                    "stored security transaction has unknown branch".into(),
                ));
            }
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
    revoke_proposal, revoke_command_outcome, terminal_outcome, recovery_completion, canonical_request";

async fn lock_transaction_identity(
    conn: &mut AsyncPgConnection,
    transaction_id: &str,
) -> Result<(), PgTransactionError> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(format!("security-transaction:{transaction_id}"))
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}

async fn require_transaction_owner(
    conn: &mut AsyncPgConnection,
    transaction_id: &str,
    expected: &arkret_wire::AccountId,
) -> PersistenceResult<()> {
    let transaction_uuid = ids::parse_typed_uuid(transaction_id, "transaction")
        .ok_or_else(|| PersistenceError::SchemaViolation("malformed transaction_id".into()))?;
    let row = sql_query("SELECT jsonb_build_object('principal_id',principal_id,'station_id',station_id) AS payload FROM security_transactions WHERE id=$1")
        .bind::<sql_types::Uuid,_>(transaction_uuid)
        .get_result::<crate::JsonPayloadRow>(&mut *conn).await.optional()
        .map_err(PersistenceError::database)?;
    if let Some(row) = row {
        let actual: arkret_wire::AccountId =
            serde_json::from_value(row.payload).map_err(PersistenceError::database)?;
        if &actual != expected {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: security transaction identity belongs to another Account"
                    .into(),
            ));
        }
    }
    Ok(())
}

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
    let owner = if for_update {
        let owner = sql_query("SELECT jsonb_build_object('principal_id',principal_id,'station_id',station_id) AS payload FROM security_transactions WHERE id=$1")
            .bind::<sql_types::Uuid,_>(transaction_uuid).get_result::<crate::JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let Some(owner) = owner else {
            return Ok(None);
        };
        let account: arkret_wire::AccountId =
            serde_json::from_value(owner.payload).map_err(PersistenceError::database)?;
        crate::pcr_private_authority::require_active_account_owner(conn, &account).await?;
        Some(account)
    } else {
        None
    };
    let record = sql_query(format!(
        "SELECT {COLUMNS} FROM security_transactions WHERE id = $1 AND canonical_request IS NOT NULL{lock}"
    ))
    .bind::<sql_types::Uuid, _>(transaction_uuid)
    .get_result::<SecurityTransactionRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(SecurityTransactionRecord::try_from)
    .transpose()?;
    if let (Some(owner), Some(record)) = (&owner, &record)
        && record.resource.account_id() != owner
    {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: security transaction changed its immutable Account owner".into(),
        ));
    }
    Ok(record)
}

async fn load_backup_erase_progress(
    conn: &mut AsyncPgConnection,
    transaction_id: &str,
    for_update: bool,
) -> PersistenceResult<Option<BackupSeriesEraseProgressRecord>> {
    if for_update && load_one(conn, transaction_id, true).await?.is_none() {
        return Ok(None);
    }
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
    crate::pcr_private_authority::require_active_account_owner(conn, record.resource.account_id())
        .await?;
    let resource = &record.resource;
    let rotation = match resource {
        SecurityTransaction::SecurityRotation(r) => Some(r),
        _ => None,
    };
    let completion = match resource {
        SecurityTransaction::Recovery(c) => Some(c),
        _ => None,
    };
    let created_at = match resource {
        SecurityTransaction::SecurityRotation(r) => r.created_at,
        SecurityTransaction::Recovery(c) => c.created_at,
    };
    sql_query("INSERT INTO security_transactions (id,kind,principal_id,station_id,authorizing_device_id,expires_at,created_at,request_digest,prepared_plan,prepared_plan_digest,accepted_steps,revoke_proposal,revoke_command_outcome,terminal_outcome,recovery_completion,canonical_request) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)")
        .bind::<sql_types::Uuid,_>(ids::typed_uuid_part_expect_internal(resource.transaction_id().as_str()))
        .bind::<Text,_>(if completion.is_some() { "recovery" } else { "security_rotation" })
        .bind::<Text,_>(resource.account_id().principal_id.as_str())
        .bind::<Text,_>(resource.account_id().station_id.as_str())
        .bind::<Nullable<Text>,_>(rotation.map(|r| r.authorizing_device_id.as_str()))
        .bind::<Nullable<Timestamptz>,_>(rotation.map(|r| r.expires_at))
        .bind::<Timestamptz,_>(created_at)
        .bind::<Nullable<Text>,_>(rotation.map(|r| r.request_digest.as_str()))
        .bind::<Nullable<Jsonb>,_>(rotation.map(|r| serde_json::to_value(&r.prepared_plan)).transpose().map_err(PersistenceError::database)?)
        .bind::<Nullable<Text>,_>(rotation.map(|r| r.prepared_plan_digest.as_str()))
        .bind::<Nullable<Jsonb>,_>(rotation.map(|r| serde_json::to_value(&r.accepted_steps)).transpose().map_err(PersistenceError::database)?)
        .bind::<Nullable<Jsonb>,_>(rotation.and_then(|r| r.revoke_proposal.as_ref()).map(serde_json::to_value).transpose().map_err(PersistenceError::database)?)
        .bind::<Nullable<Jsonb>,_>(rotation.and_then(|r| r.revoke_command_outcome.as_ref()).map(serde_json::to_value).transpose().map_err(PersistenceError::database)?)
        .bind::<Nullable<Jsonb>,_>(rotation.and_then(|r| r.terminal_outcome.as_ref()).map(serde_json::to_value).transpose().map_err(PersistenceError::database)?)
        .bind::<Nullable<Jsonb>,_>(completion.map(serde_json::to_value).transpose().map_err(PersistenceError::database)?)
        .bind::<Binary,_>(&record.canonical_request).execute(conn).await.map(|_|()).map_err(PersistenceError::database)
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
         FROM security_transaction_step_outcomes WHERE transaction_id = $1 AND step = $2 \
         AND canonical_request IS NOT NULL AND response IS NOT NULL",
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
    let rotation = record.rotation()?;
    sql_query(
        "UPDATE security_transactions SET accepted_steps = $2, \
         revoke_proposal = $3, revoke_command_outcome = $4, \
         terminal_outcome = $5 WHERE id = $1",
    )
    .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(
        record.resource.transaction_id().as_str(),
    ))
    .bind::<Jsonb, _>(
        serde_json::to_value(&rotation.accepted_steps)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Nullable<Jsonb>, _>(
        rotation
            .revoke_proposal
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Nullable<Jsonb>, _>(
        rotation
            .revoke_command_outcome
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Nullable<Jsonb>, _>(
        rotation
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

/// Where the durable step attempt for an accepted step comes from.
///
/// Rotation workers freeze request bytes before participant side effects.
/// A local co-transaction Rotation unit may create its attempt with its outcome.
/// Recovery does not create step records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StepAttemptSource {
    DurablyBegun,
    CoCommittedWithOutcome,
}

/// Accept one security-transaction step inside a transaction the caller owns.
///
/// This is the whole terminal ledger write: the first response bytes, the
/// mutable Rotation resource fields. Recovery has its own indivisible unit.
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
    let transaction_id = record.resource.transaction_id().as_str().to_owned();
    if outcome.transaction_id != transaction_id {
        return Err(PersistenceError::SchemaViolation(
            "security transaction step outcome belongs to a different transaction".to_owned(),
        )
        .into());
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
    async fn prepare_content_recoveries(
        &self,
        service: &arkret_wire::DidCoreId,
        materials: Option<&dyn coland_storage::RecoveryInventoryPublicMaterial>,
    ) -> PersistenceResult<usize> {
        recovery_inventory::sweep(&self.pool, service, materials).await
    }

    async fn read_content_inventory(
        &self,
        reader: &coland_storage::HumanPcrHistoryReader,
        authorization: &arkret_wire::EventId,
        reference: &arkret_wire::BlobRef,
    ) -> PersistenceResult<coland_storage::HumanPcrHistoryRead<Vec<u8>>> {
        recovery_inventory::read(&self.pool, reader, authorization, reference).await
    }

    async fn human_content_recovery_preparation(
        &self,
        reader: &coland_storage::HumanPcrHistoryReader,
        authorization: &arkret_wire::EventId,
    ) -> PersistenceResult<
        coland_storage::HumanPcrHistoryRead<arkret_models_crypto::ContentRecoveryPreparation>,
    > {
        content_recovery_preparation::read(&self.pool, reader, authorization).await
    }
    async fn human_content_recovery_source(
        &self,
        reader: &coland_storage::HumanPcrHistoryReader,
    ) -> PersistenceResult<arkret_wire::RecoveryCompletionAttestation> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            content_recovery_source::qualify_in_connection(conn, reader)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

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
            "SELECT id FROM security_transactions WHERE kind='security_rotation' AND canonical_request IS NOT NULL \
             AND terminal_outcome IS NULL AND jsonb_array_length(accepted_steps) < 4 \
             AND account_private_state_allowed(principal_id,station_id) \
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
    ) -> PersistenceResult<SecurityTransactionRecord> {
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
        let rotation = record.rotation()?;
        rotation
            .validate_structural()
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        if rotation.revoke_proposal.is_some() || rotation.revoke_command_outcome.is_some() {
            return Err(PersistenceError::Conflict(
                "Rotation proposal/result require their guarded unit".into(),
            ));
        }
        arkret_canonical::canonical::verify_digest(
            &record.canonical_request,
            rotation.request_digest.as_str(),
        )
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        let transaction_id = rotation.transaction_id.to_string();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::pcr_private_authority::require_active_account_owner(
                conn,
                record.resource.account_id(),
            )
            .await?;
            // The advisory lock covers absence as well as existing rows. The
            // accepted identity is never overwritten by a racing first writer.
            lock_transaction_identity(conn, &transaction_id).await?;
            require_transaction_owner(conn, &transaction_id, record.resource.account_id()).await?;
            if let Some(existing) = load_one(conn, &transaction_id, true).await? {
                super::classify_security_transaction_first_write(
                    Some(&existing.canonical_request),
                    &record.canonical_request,
                )?;
                return Ok(existing);
            }
            insert_one(conn, &record).await?;
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
        let transaction_id = record.resource.transaction_id().as_str().to_owned();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            require_transaction_owner(conn, &transaction_id, record.resource.account_id()).await?;
            let existing = load_one(conn, &transaction_id, true)
                .await?
                .ok_or_else(|| {
                    PersistenceError::NotFound(format!(
                        "transaction_id `{transaction_id}` not found"
                    ))
                })?;
            super::validate_security_transaction_update(&existing, &record)?;
            if existing.rotation()?.revoke_command_outcome
                != record.rotation()?.revoke_command_outcome
            {
                return Err(PersistenceError::Conflict(
                    "revoke command result requires its guarded terminal unit".to_owned(),
                )
                .into());
            }
            if record.rotation()?.accepted_steps != existing.rotation()?.accepted_steps {
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
                record.rotation()?;
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
        let transaction_id = record.resource.transaction_id().as_str().to_owned();
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
