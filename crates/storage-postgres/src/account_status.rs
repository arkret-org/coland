use arkret_models_collaboration::account_status::{AccountStatusReceipt, AccountStatusRecord};
use coland_storage::{
    AccountStatusAffectedServiceObservation, AccountStatusPropagationProjection,
    AccountStatusPropagationProjectionState, AccountStatusPropagationProjectionTransition,
    classify_account_status_replica_append,
};

use super::{
    AccountStatusReplicaAppend, AccountStatusReplicaStore, AsyncConnection, BigInt, Jsonb,
    OptionalExtension, PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    QueryableByName, RunQueryDsl, Text, Timestamptz, async_trait, pg_conn, sql_query,
};

/// The durable replica head for one `(account_authority_id, account_id)` pair:
/// the accepted record and the receipt that acknowledged it.
type ReplicaHead = (AccountStatusRecord, AccountStatusReceipt);

pub struct PgAccountStatusReplicaStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct RecordRow {
    #[diesel(sql_type = Jsonb)]
    record: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    receipt: serde_json::Value,
}

#[derive(QueryableByName)]
struct AffectedServiceRow {
    #[diesel(sql_type = Text)]
    service_id: String,
}

#[derive(QueryableByName)]
struct AffectedSourceRow {
    #[diesel(sql_type = Text)]
    source: String,
}

#[derive(QueryableByName)]
struct AffectedCandidateRow {
    #[diesel(sql_type = Text)]
    source: String,
    #[diesel(sql_type = Text)]
    candidate: String,
}

#[derive(QueryableByName)]
struct PropagationProjectionRow {
    #[diesel(sql_type = Text)]
    account_authority_id: String,
    #[diesel(sql_type = Jsonb)]
    account_id: serde_json::Value,
    #[diesel(sql_type = Text)]
    account_status_record_id: String,
    #[diesel(sql_type = BigInt)]
    status_seq: i64,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = BigInt)]
    pending_destination_count: i64,
    #[diesel(sql_type = Timestamptz)]
    deadline_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct PendingPropagationCountRow {
    #[diesel(sql_type = BigInt)]
    pending_destination_count: i64,
}

fn decode_propagation_projection(
    row: PropagationProjectionRow,
) -> PersistenceResult<AccountStatusPropagationProjection> {
    let state = match row.state.as_str() {
        "scheduled" => AccountStatusPropagationProjectionState::Scheduled,
        "complete" => AccountStatusPropagationProjectionState::Complete,
        "incomplete" => AccountStatusPropagationProjectionState::Incomplete,
        other => {
            return Err(PersistenceError::Internal(format!(
                "stored account-status propagation state is invalid: {other}"
            )));
        }
    };
    Ok(AccountStatusPropagationProjection {
        account_authority_id: arkret_wire::DidCoreId::new(row.account_authority_id)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        account_id: serde_json::from_value(row.account_id).map_err(|error| {
            PersistenceError::Internal(format!(
                "stored account-status propagation account id is invalid: {error}"
            ))
        })?,
        account_status_record_id: arkret_wire::AccountStatusRecordId::new(
            row.account_status_record_id,
        )
        .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        status_seq: u64::try_from(row.status_seq).map_err(|_| {
            PersistenceError::Internal(
                "stored account-status propagation sequence is negative".to_owned(),
            )
        })?,
        state,
        pending_destination_count: u64::try_from(row.pending_destination_count).map_err(|_| {
            PersistenceError::Internal(
                "stored account-status propagation pending count is negative".to_owned(),
            )
        })?,
        deadline_at: row.deadline_at,
        updated_at: row.updated_at,
    })
}

fn affected_source(
    value: &str,
) -> PersistenceResult<coland_storage::AccountStatusAffectedServiceSource> {
    use coland_storage::AccountStatusAffectedServiceSource as Source;
    match value {
        "session" => Ok(Source::Session),
        "device" => Ok(Source::Device),
        "key_package" => Ok(Source::KeyPackage),
        "to_device" => Ok(Source::ToDevice),
        "push_route" => Ok(Source::PushRoute),
        "principal_locator" => Ok(Source::PrincipalLocator),
        "realm_membership" => Ok(Source::RealmMembership),
        other => Err(PersistenceError::Internal(format!(
            "stored affected-service source is invalid: {other}"
        ))),
    }
}

fn push_unique_observation(
    observations: &mut Vec<AccountStatusAffectedServiceObservation>,
    service_id: arkret_wire::DidCoreId,
    source: coland_storage::AccountStatusAffectedServiceSource,
    observed_at: chrono::DateTime<chrono::Utc>,
) {
    if observations
        .iter()
        .any(|observation| observation.service_id == service_id && observation.source == source)
    {
        return;
    }
    observations.push(AccountStatusAffectedServiceObservation {
        service_id,
        source,
        observed_at,
    });
}

fn decode_record(row: &RecordRow) -> PersistenceResult<AccountStatusRecord> {
    serde_json::from_value(row.record.clone()).map_err(|error| {
        PersistenceError::Internal(format!("stored account-status record is invalid: {error}"))
    })
}

fn decode_receipt(row: &RecordRow) -> PersistenceResult<AccountStatusReceipt> {
    serde_json::from_value(row.receipt.clone()).map_err(|error| {
        PersistenceError::Internal(format!("stored account-status receipt is invalid: {error}"))
    })
}

fn encode_account_id(account: &arkret_wire::AccountId) -> PersistenceResult<serde_json::Value> {
    serde_json::to_value(account).map_err(|error| {
        PersistenceError::Internal(format!("account identity cannot be encoded: {error}"))
    })
}

#[async_trait]
impl AccountStatusReplicaStore for PgAccountStatusReplicaStore {
    async fn append(
        &self,
        record: &AccountStatusRecord,
        receipt: &AccountStatusReceipt,
    ) -> PersistenceResult<AccountStatusReplicaAppend> {
        receipt.validate_for_record(record).map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "account-status record/receipt pair is invalid: {error}"
            ))
        })?;
        let mut conn = pg_conn(&self.pool).await?;
        let record = record.clone();
        let receipt = receipt.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let authority = record.account_authority_id.to_string();
            let account = encode_account_id(&record.account_id)?;
            let lock_key = format!("account-status:{authority}:{}", record.account_id);
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&lock_key)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;

            let head = sql_query(
                "SELECT record, receipt FROM account_status_replica_records \
                 WHERE account_authority_id = $1 AND account_id = $2 \
                 ORDER BY status_seq DESC LIMIT 1",
            )
            .bind::<Text, _>(&authority)
            .bind::<Jsonb, _>(&account)
            .get_result::<RecordRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .map(|row| -> PersistenceResult<ReplicaHead> {
                Ok((decode_record(&row)?, decode_receipt(&row)?))
            })
            .transpose()?;

            if let Some(outcome) = classify_account_status_replica_append(&record, head.as_ref()) {
                return Ok(outcome);
            }

            sql_query(
                "INSERT INTO account_status_replica_records \
                 (account_authority_id, account_id, status_seq, record_id, record, receipt) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind::<Text, _>(&authority)
            .bind::<Jsonb, _>(&account)
            .bind::<BigInt, _>(i64::try_from(record.status_seq).map_err(|_| {
                PersistenceError::SchemaViolation(
                    "account-status sequence exceeds PostgreSQL bigint".to_owned(),
                )
            })?)
            .bind::<Text, _>(record.account_status_record_id.as_str())
            .bind::<Jsonb, _>(serde_json::to_value(&record).map_err(|error| {
                PersistenceError::Internal(format!(
                    "account-status record cannot be encoded: {error}"
                ))
            })?)
            .bind::<Jsonb, _>(serde_json::to_value(&receipt).map_err(|error| {
                PersistenceError::Internal(format!(
                    "account-status receipt cannot be encoded: {error}"
                ))
            })?)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(AccountStatusReplicaAppend::Accepted(receipt))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn current(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<AccountStatusRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE account_authority_id = $1 AND account_id = $2 \
             ORDER BY status_seq DESC LIMIT 1",
        )
        .bind::<Text, _>(account_authority_id)
        .bind::<Jsonb, _>(encode_account_id(account_id)?)
        .get_result::<RecordRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| decode_record(&row))
        .transpose()
    }

    async fn resolve(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
        from_status_seq: u64,
        limit: u16,
    ) -> PersistenceResult<Vec<AccountStatusRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE account_authority_id = $1 AND account_id = $2 AND status_seq >= $3 \
             ORDER BY status_seq ASC LIMIT $4",
        )
        .bind::<Text, _>(account_authority_id)
        .bind::<Jsonb, _>(encode_account_id(account_id)?)
        .bind::<BigInt, _>(i64::try_from(from_status_seq).map_err(|_| {
            PersistenceError::SchemaViolation(
                "account-status sequence exceeds PostgreSQL bigint".to_owned(),
            )
        })?)
        .bind::<BigInt, _>(i64::from(limit))
        .load::<RecordRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(|row| decode_record(&row)).collect()
    }

    async fn erasure_pending(&self, limit: u16) -> PersistenceResult<Vec<AccountStatusRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE record #>> '{status}' = 'erasure_pending' \
             ORDER BY accepted_at, account_authority_id, account_id, status_seq LIMIT $1",
        )
        .bind::<BigInt, _>(i64::from(limit))
        .load::<RecordRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(|row| decode_record(&row)).collect()
    }

    async fn receipt(
        &self,
        account_authority_id: &str,
        account_id: &arkret_wire::AccountId,
        status_seq: u64,
    ) -> PersistenceResult<Option<AccountStatusReceipt>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT record, receipt FROM account_status_replica_records \
             WHERE account_authority_id = $1 AND account_id = $2 AND status_seq = $3",
        )
        .bind::<Text, _>(account_authority_id)
        .bind::<Jsonb, _>(encode_account_id(account_id)?)
        .bind::<BigInt, _>(i64::try_from(status_seq).map_err(|_| {
            PersistenceError::SchemaViolation(
                "account-status sequence exceeds PostgreSQL bigint".to_owned(),
            )
        })?)
        .get_result::<RecordRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| decode_receipt(&row))
        .transpose()
    }

    async fn merge_affected_services(
        &self,
        account_id: &arkret_wire::AccountId,
        observations: &[AccountStatusAffectedServiceObservation],
        max_services: usize,
    ) -> PersistenceResult<Vec<arkret_wire::DidCoreId>> {
        if max_services == 0 {
            return Err(PersistenceError::SchemaViolation(
                "account-status affected-service limit must be positive".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        let account = encode_account_id(account_id)?;
        let observations = observations.to_vec();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let lock_key = format!("account-status-affected:{account_id}");
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&lock_key)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;

            let mut services = sql_query(
                "SELECT DISTINCT service_id FROM account_status_affected_services \
                 WHERE account_id = $1 ORDER BY service_id",
            )
            .bind::<Jsonb, _>(&account)
            .load::<AffectedServiceRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
            .into_iter()
            .map(|row| row.service_id)
            .collect::<std::collections::BTreeSet<_>>();
            services.extend(
                observations
                    .iter()
                    .map(|observation| observation.service_id.as_str().to_owned()),
            );
            if services.len() > max_services {
                return Err(PersistenceError::SchemaViolation(format!(
                    "account-status affected-service set exceeds {max_services}"
                ))
                .into());
            }
            for observation in &observations {
                sql_query(
                    "INSERT INTO account_status_affected_services \
                     (account_id, service_id, source, first_observed_at, last_observed_at) \
                     VALUES ($1, $2, $3, $4, $4) \
                     ON CONFLICT (account_id, service_id, source) DO UPDATE SET \
                     last_observed_at = GREATEST(account_status_affected_services.last_observed_at, EXCLUDED.last_observed_at)",
                )
                .bind::<Jsonb, _>(&account)
                .bind::<Text, _>(observation.service_id.as_str())
                .bind::<Text, _>(observation.source.as_str())
                .bind::<Timestamptz, _>(observation.observed_at)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            }
            Ok(services
                .into_iter()
                .map(|service_id| {
                    arkret_wire::DidCoreId::new(service_id).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored affected service id is invalid: {error}"
                        ))
                    })
                })
                .collect::<PersistenceResult<Vec<_>>>()?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn discover_affected_services(
        &self,
        account_id: &arkret_wire::AccountId,
        holder_service_id: &arkret_wire::DidCoreId,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Vec<AccountStatusAffectedServiceObservation>> {
        let mut conn = pg_conn(&self.pool).await?;
        let account_actor = arkret_wire::ActorId::account(account_id.clone()).to_string();
        let account = encode_account_id(account_id)?;
        let local_sources = sql_query(
            "SELECT 'session'::text AS source WHERE EXISTS (SELECT 1 FROM sessions WHERE actor_id = $1) \
             UNION ALL SELECT 'device'::text WHERE EXISTS (SELECT 1 FROM devices WHERE actor_id = $1) \
             UNION ALL SELECT 'key_package'::text WHERE EXISTS (SELECT 1 FROM mls_key_packages WHERE actor_id = $1) \
             UNION ALL SELECT 'to_device'::text WHERE EXISTS (SELECT 1 FROM device_messages WHERE sender = $1 OR recipient = $1) \
             UNION ALL SELECT 'push_route'::text WHERE EXISTS (SELECT 1 FROM push_devices WHERE payload->'account_id' = $2) \
             UNION ALL SELECT 'principal_locator'::text WHERE EXISTS (SELECT 1 FROM invite_locators WHERE subject_id = $1 OR recipient_id = $1)",
        )
        .bind::<Text, _>(&account_actor)
        .bind::<Jsonb, _>(&account)
        .load::<AffectedSourceRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;

        let mut observations = Vec::new();
        for row in local_sources {
            push_unique_observation(
                &mut observations,
                holder_service_id.clone(),
                affected_source(&row.source)?,
                observed_at,
            );
        }

        // Session audiences are explicit service identities. They are not
        // inferred from a URL or deployment config.
        let session_candidates = sql_query(
            "SELECT DISTINCT 'session'::text AS source, audience AS candidate \
             FROM sessions WHERE actor_id = $1",
        )
        .bind::<Text, _>(&account_actor)
        .load::<AffectedCandidateRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        for row in session_candidates {
            if let Ok(service_id) = arkret_wire::DidCoreId::new(row.candidate) {
                push_unique_observation(
                    &mut observations,
                    service_id,
                    affected_source(&row.source)?,
                    observed_at,
                );
            }
        }

        // To-device and locator rows can name a peer only through the typed
        // counterpart ActorId. Malformed or principal-only strings do not
        // broaden the affected set.
        let actor_candidates = sql_query(
            "SELECT DISTINCT 'to_device'::text AS source, \
                 CASE WHEN sender = $1 THEN recipient ELSE sender END AS candidate \
             FROM device_messages WHERE sender = $1 OR recipient = $1 \
             UNION ALL \
             SELECT DISTINCT 'principal_locator'::text AS source, \
                 CASE WHEN subject_id = $1 THEN recipient_id ELSE subject_id END AS candidate \
             FROM invite_locators WHERE subject_id = $1 OR recipient_id = $1",
        )
        .bind::<Text, _>(&account_actor)
        .load::<AffectedCandidateRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        for row in actor_candidates {
            let Ok(actor) = serde_json::from_str::<arkret_wire::ActorId>(&row.candidate) else {
                continue;
            };
            push_unique_observation(
                &mut observations,
                actor.route_service_id().clone(),
                affected_source(&row.source)?,
                observed_at,
            );
        }
        Ok(observations)
    }

    async fn affected_services(
        &self,
        account_id: &arkret_wire::AccountId,
        limit: usize,
    ) -> PersistenceResult<Vec<arkret_wire::DidCoreId>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT DISTINCT service_id FROM account_status_affected_services \
             WHERE account_id = $1 ORDER BY service_id LIMIT $2",
        )
        .bind::<Jsonb, _>(encode_account_id(account_id)?)
        .bind::<BigInt, _>(i64::try_from(limit).map_err(|_| {
            PersistenceError::SchemaViolation(
                "account-status affected-service read limit exceeds PostgreSQL bigint".to_owned(),
            )
        })?)
        .load::<AffectedServiceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                arkret_wire::DidCoreId::new(row.service_id).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored affected service id is invalid: {error}"
                    ))
                })
            })
            .collect()
    }

    async fn begin_propagation(
        &self,
        record: &AccountStatusRecord,
        destinations: &[arkret_wire::DidCoreId],
        deadline_at: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<AccountStatusPropagationProjection> {
        let destinations = destinations
            .iter()
            .map(ToString::to_string)
            .collect::<std::collections::BTreeSet<_>>();
        if destinations.len() > 256 {
            return Err(PersistenceError::SchemaViolation(
                "account-status propagation target set exceeds 256".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        let account = encode_account_id(&record.account_id)?;
        let record = record.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(format!("account-status-propagation:{}", record.account_status_record_id))
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            let existing = sql_query(
                "SELECT p.account_authority_id, p.account_id, p.account_status_record_id, p.status_seq, \
                 p.state, (SELECT COUNT(*) FROM account_status_propagation_targets t WHERE \
                 t.account_status_record_id = p.account_status_record_id AND t.acknowledged_at IS NULL) \
                 AS pending_destination_count, p.deadline_at, p.updated_at \
                 FROM account_status_propagations p WHERE p.account_status_record_id = $1",
            )
            .bind::<Text, _>(record.account_status_record_id.as_str())
            .get_result::<PropagationProjectionRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            if let Some(existing) = existing {
                let existing_destinations = sql_query(
                    "SELECT destination_id AS service_id FROM account_status_propagation_targets \
                     WHERE account_status_record_id = $1 ORDER BY destination_id",
                )
                .bind::<Text, _>(record.account_status_record_id.as_str())
                .load::<AffectedServiceRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?
                .into_iter()
                .map(|row| row.service_id)
                .collect::<std::collections::BTreeSet<_>>();
                if existing_destinations != destinations {
                    return Err(PersistenceError::Conflict(
                        "account-status propagation replay target set mismatch".to_owned(),
                    )
                    .into());
                }
                return Ok(decode_propagation_projection(existing)?);
            }
            let state = if destinations.is_empty() {
                AccountStatusPropagationProjectionState::Complete
            } else {
                AccountStatusPropagationProjectionState::Scheduled
            };
            sql_query(
                "INSERT INTO account_status_propagations \
                 (account_authority_id, account_id, account_status_record_id, status_seq, state, \
                  deadline_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $7)",
            )
            .bind::<Text, _>(record.account_authority_id.as_str())
            .bind::<Jsonb, _>(&account)
            .bind::<Text, _>(record.account_status_record_id.as_str())
            .bind::<BigInt, _>(i64::try_from(record.status_seq).map_err(|_| {
                PersistenceError::SchemaViolation(
                    "account-status propagation sequence exceeds PostgreSQL bigint".to_owned(),
                )
            })?)
            .bind::<Text, _>(state.as_str())
            .bind::<Timestamptz, _>(deadline_at)
            .bind::<Timestamptz, _>(now)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            for destination in &destinations {
                sql_query(
                    "INSERT INTO account_status_propagation_targets \
                     (account_status_record_id, destination_id) VALUES ($1, $2)",
                )
                .bind::<Text, _>(record.account_status_record_id.as_str())
                .bind::<Text, _>(destination)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            }
            Ok(AccountStatusPropagationProjection {
                account_authority_id: record.account_authority_id,
                account_id: record.account_id,
                account_status_record_id: record.account_status_record_id,
                status_seq: record.status_seq,
                state,
                pending_destination_count: destinations.len() as u64,
                deadline_at,
                updated_at: now,
            })
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn acknowledge_propagation_destination(
        &self,
        account_status_record_id: &arkret_wire::AccountStatusRecordId,
        destination_id: &arkret_wire::DidCoreId,
        acknowledged_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<AccountStatusPropagationProjectionTransition>> {
        let mut conn = pg_conn(&self.pool).await?;
        let record_id = account_status_record_id.to_string();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let previous = sql_query(
                "SELECT p.account_authority_id, p.account_id, p.account_status_record_id, p.status_seq, \
                 p.state, (SELECT COUNT(*) FROM account_status_propagation_targets t WHERE \
                 t.account_status_record_id = p.account_status_record_id AND t.acknowledged_at IS NULL) \
                 AS pending_destination_count, p.deadline_at, p.updated_at \
                 FROM account_status_propagations p WHERE p.account_status_record_id = $1 FOR UPDATE",
            )
            .bind::<Text, _>(&record_id)
            .get_result::<PropagationProjectionRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            let Some(previous) = previous else {
                return Ok(None);
            };
            let previous = decode_propagation_projection(previous)?;
            let updated = sql_query(
                "UPDATE account_status_propagation_targets SET acknowledged_at = COALESCE(acknowledged_at, $3) \
                 WHERE account_status_record_id = $1 AND destination_id = $2",
            )
            .bind::<Text, _>(&record_id)
            .bind::<Text, _>(destination_id.as_str())
            .bind::<Timestamptz, _>(acknowledged_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            if updated == 0 {
                return Ok(None);
            }
            let pending = sql_query(
                "SELECT COUNT(*) AS pending_destination_count FROM account_status_propagation_targets \
                 WHERE account_status_record_id = $1 AND acknowledged_at IS NULL",
            )
            .bind::<Text, _>(&record_id)
            .get_result::<PendingPropagationCountRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
            .pending_destination_count;
            let state = if pending == 0 {
                AccountStatusPropagationProjectionState::Complete
            } else if acknowledged_at >= previous.deadline_at {
                AccountStatusPropagationProjectionState::Incomplete
            } else {
                AccountStatusPropagationProjectionState::Scheduled
            };
            sql_query(
                "UPDATE account_status_propagations SET state = $2, updated_at = $3 \
                 WHERE account_status_record_id = $1",
            )
            .bind::<Text, _>(&record_id)
            .bind::<Text, _>(state.as_str())
            .bind::<Timestamptz, _>(acknowledged_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            let projection = AccountStatusPropagationProjection {
                state,
                pending_destination_count: u64::try_from(pending).map_err(|_| {
                    PersistenceError::Internal("negative propagation pending count".to_owned())
                })?,
                updated_at: acknowledged_at,
                ..previous.clone()
            };
            // If the final ack is the first observer after the deadline, the
            // durable state can settle directly on `complete`, but the timeout
            // boundary still occurred and must remain auditable. Report both
            // transitions so callers append incomplete then clear evidence.
            let crossed_deadline = previous.pending_destination_count > 0
                && previous.state == AccountStatusPropagationProjectionState::Scheduled
                && acknowledged_at >= previous.deadline_at;
            Ok(Some(AccountStatusPropagationProjectionTransition {
                became_incomplete: previous.state
                    != AccountStatusPropagationProjectionState::Incomplete
                    && (state == AccountStatusPropagationProjectionState::Incomplete
                        || crossed_deadline),
                became_complete: previous.state
                    != AccountStatusPropagationProjectionState::Complete
                    && state == AccountStatusPropagationProjectionState::Complete,
                projection,
            }))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn current_propagation_projection(
        &self,
        account_id: &arkret_wire::AccountId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<AccountStatusPropagationProjectionTransition>> {
        let mut conn = pg_conn(&self.pool).await?;
        let account = encode_account_id(account_id)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let current = sql_query(
                "SELECT p.account_authority_id, p.account_id, p.account_status_record_id, p.status_seq, \
                 p.state, (SELECT COUNT(*) FROM account_status_propagation_targets t WHERE \
                 t.account_status_record_id = p.account_status_record_id AND t.acknowledged_at IS NULL) \
                 AS pending_destination_count, p.deadline_at, p.updated_at \
                 FROM account_status_propagations p WHERE p.account_id = $1 \
                 ORDER BY p.status_seq DESC LIMIT 1 FOR UPDATE",
            )
            .bind::<Jsonb, _>(&account)
            .get_result::<PropagationProjectionRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            let Some(current) = current else {
                return Ok(None);
            };
            let mut projection = decode_propagation_projection(current)?;
            let previous_state = projection.state;
            if projection.pending_destination_count == 0 {
                projection.state = AccountStatusPropagationProjectionState::Complete;
            } else if projection.state == AccountStatusPropagationProjectionState::Scheduled
                && now >= projection.deadline_at
            {
                projection.state = AccountStatusPropagationProjectionState::Incomplete;
            }
            if projection.state != previous_state {
                projection.updated_at = now;
                sql_query(
                    "UPDATE account_status_propagations SET state = $2, updated_at = $3 \
                     WHERE account_status_record_id = $1",
                )
                .bind::<Text, _>(projection.account_status_record_id.as_str())
                .bind::<Text, _>(projection.state.as_str())
                .bind::<Timestamptz, _>(now)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            }
            Ok(Some(AccountStatusPropagationProjectionTransition {
                became_incomplete: previous_state
                    != AccountStatusPropagationProjectionState::Incomplete
                    && projection.state == AccountStatusPropagationProjectionState::Incomplete,
                became_complete: previous_state
                    != AccountStatusPropagationProjectionState::Complete
                    && projection.state == AccountStatusPropagationProjectionState::Complete,
                projection,
            }))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::account_status::UnsignedAccountStatusRecord;
    use arkret_models_collaboration::objects::account_status::AccountStatus;
    use arkret_wire::{DidUrl, PayloadProof, RealmId, SchemaId};
    use coland_storage::AccountStatusAffectedServiceSource;
    use coland_storage::contract_tests::assert_account_status_replica_decision_table_contract;

    use super::*;

    #[derive(QueryableByName)]
    struct TestAccountPk {
        #[diesel(sql_type = BigInt)]
        pk: i64,
    }

    /// The shared contract pool. `COLAND_TEST_DATABASE_URL` or `DATABASE_URL`
    /// must name a reachable database; these contracts fail rather than skip.
    async fn test_pool() -> PgPool {
        crate::test_database::contract_pool().await
    }

    /// Each run claims a fresh account so the shared database cannot leak a
    /// durable head between runs.
    fn unique_namespace() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after the unix epoch")
            .as_nanos();
        format!("postgres-account-status-{nanos}")
    }

    fn propagation_record(namespace: &str) -> AccountStatusRecord {
        let base = "2026-09-20T00:00:00.000Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        let verification_method = DidUrl::new("did:web:authority.example#account-status-key")
            .expect("fixture verification method");
        let attach = |unsigned: UnsignedAccountStatusRecord| {
            let proof = PayloadProof {
                kind: "detached_jws".to_owned(),
                verification_method: verification_method.clone(),
                payload_digest: unsigned.payload_digest().expect("fixture payload digest"),
                created_at: unsigned.issued_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "eyJhbGciOiJFZDI1NTE5In0..propagation-fixture".to_owned(),
            };
            unsigned.attach_proof(proof).expect("valid fixture record")
        };
        let account_id = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:{namespace}.example")).unwrap(),
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:origin-{namespace}.example"))
                .unwrap(),
        );
        let authority = arkret_wire::DidCoreId::new("ak:did_core:web:authority.example").unwrap();
        let genesis = attach(UnsignedAccountStatusRecord {
            schema: SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
            account_authority_id: authority.clone(),
            account_id: account_id.clone(),
            principal_control_realm_id: RealmId::new(
                "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
            )
            .unwrap(),
            binding_version: 1,
            status_seq: 1,
            previous_account_status_record_id: None,
            status: AccountStatus::Active,
            reason_code: None,
            reason: None,
            issued_at: base,
            expires_at: None,
        });
        attach(UnsignedAccountStatusRecord {
            schema: SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
            account_authority_id: authority,
            account_id,
            principal_control_realm_id: genesis.principal_control_realm_id.clone(),
            binding_version: 1,
            status_seq: 2,
            previous_account_status_record_id: Some(genesis.account_status_record_id),
            status: AccountStatus::Deactivated,
            reason_code: None,
            reason: None,
            issued_at: base + chrono::Duration::seconds(1),
            expires_at: None,
        })
    }

    #[tokio::test]
    async fn postgres_adapter_satisfies_account_status_decision_table() {
        let pool = test_pool().await;
        let store = PgAccountStatusReplicaStore { pool };
        assert_account_status_replica_decision_table_contract(&store, &unique_namespace()).await;
    }

    #[tokio::test]
    async fn postgres_affected_service_index_is_durable_bounded_and_source_deduplicated() {
        let pool = test_pool().await;
        let namespace = unique_namespace();
        let account_id = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:{namespace}.example")).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:origin.example").unwrap(),
        );
        let service_a = arkret_wire::DidCoreId::new("ak:did_core:web:target-a.example").unwrap();
        let service_b = arkret_wire::DidCoreId::new("ak:did_core:web:target-b.example").unwrap();
        let service_c = arkret_wire::DidCoreId::new("ak:did_core:web:target-c.example").unwrap();
        let observed_at = chrono::Utc::now();
        let store = PgAccountStatusReplicaStore { pool: pool.clone() };

        let services = store
            .merge_affected_services(
                &account_id,
                &[
                    AccountStatusAffectedServiceObservation {
                        service_id: service_a.clone(),
                        source: AccountStatusAffectedServiceSource::RealmMembership,
                        observed_at,
                    },
                    AccountStatusAffectedServiceObservation {
                        service_id: service_a.clone(),
                        source: AccountStatusAffectedServiceSource::Session,
                        observed_at,
                    },
                    AccountStatusAffectedServiceObservation {
                        service_id: service_b.clone(),
                        source: AccountStatusAffectedServiceSource::Device,
                        observed_at,
                    },
                ],
                2,
            )
            .await
            .expect("two distinct services fit the configured ceiling");
        assert_eq!(services, vec![service_a.clone(), service_b.clone()]);

        let error = store
            .merge_affected_services(
                &account_id,
                &[AccountStatusAffectedServiceObservation {
                    service_id: service_c,
                    source: AccountStatusAffectedServiceSource::PushRoute,
                    observed_at,
                }],
                2,
            )
            .await
            .expect_err("a third distinct service must fail closed");
        assert!(matches!(error, PersistenceError::SchemaViolation(_)));

        // A new adapter instance models process restart: durable targets remain,
        // while the rejected over-limit observation left no partial row behind.
        let restarted = PgAccountStatusReplicaStore { pool };
        assert_eq!(
            restarted
                .affected_services(&account_id, 3)
                .await
                .expect("durable index is readable after restart"),
            vec![service_a, service_b]
        );
    }

    #[tokio::test]
    async fn postgres_discovers_the_closed_local_state_source_families_for_exact_account() {
        let pool = test_pool().await;
        let namespace = unique_namespace();
        let account_id = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:{namespace}.example")).unwrap(),
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:origin-{namespace}.example"))
                .unwrap(),
        );
        let account_actor = arkret_wire::ActorId::account(account_id.clone()).to_string();
        let holder =
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:holder-{namespace}.example"))
                .unwrap();
        let peer = arkret_wire::DidCoreId::new(format!("ak:did_core:web:peer-{namespace}.example"))
            .unwrap();
        let peer_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!(
                "ak:did_core:web:peer-principal-{namespace}.example"
            ))
            .unwrap(),
            peer.clone(),
        ))
        .to_string();
        let now = chrono::Utc::now();
        let mut conn = pg_conn(&pool).await.expect("contract database connection");
        let account_pk = sql_query(
            "INSERT INTO accounts (principal_id, station_id, payload) VALUES ($1, $2, '{}'::jsonb) RETURNING pk",
        )
        .bind::<Text, _>(account_id.principal_id.as_str())
        .bind::<Text, _>(account_id.station_id.as_str())
        .get_result::<TestAccountPk>(&mut conn)
        .await
        .expect("insert exact account")
        .pk;
        sql_query(
            "INSERT INTO sessions (id, account_pk, actor_id, device_id, audience, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind::<Text, _>(format!("session-{namespace}"))
        .bind::<BigInt, _>(account_pk)
        .bind::<Text, _>(&account_actor)
        .bind::<Text, _>(format!("device-{namespace}"))
        .bind::<Text, _>(peer.as_str())
        .bind::<Timestamptz, _>(now + chrono::Duration::hours(1))
        .execute(&mut conn)
        .await
        .expect("insert session source");
        sql_query(
            "INSERT INTO device_inventory_station (singleton, station_id) VALUES (TRUE, $1) \
             ON CONFLICT (singleton) DO NOTHING",
        )
        .bind::<Text, _>(holder.as_str())
        .execute(&mut conn)
        .await
        .expect("ensure device inventory owner");
        sql_query(
            "INSERT INTO devices (id, actor_id, device_id, payload) VALUES ($1, $2, $3, '{}'::jsonb)",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::new_v4())
        .bind::<Text, _>(&account_actor)
        .bind::<Text, _>(format!("inventory-device-{namespace}"))
        .execute(&mut conn)
        .await
        .expect("insert device source");
        sql_query(
            "INSERT INTO mls_key_packages \
             (id, keypackage_ref, keypackage_digest, owner_account_id, actor_id, device_id, \
              key_package_bytes, capabilities, capabilities_digest, last_resort, \
              lifetime_not_before, lifetime_not_after, device_authorize_event_id, created_at) \
             VALUES ($1, $2, $3, (SELECT jsonb_build_object('principal_id',principal_id,'station_id',station_id) FROM accounts WHERE pk=$4), $5, $6, $7, '[]'::jsonb, $8, FALSE, 1, 2, $9, 1)",
        )
        .bind::<Text, _>(format!("key-package-{namespace}"))
        .bind::<Text, _>(format!("key-package-ref-{namespace}"))
        .bind::<Text, _>(format!("sha256:{:0<64}", namespace))
        .bind::<BigInt, _>(account_pk)
        .bind::<Text, _>(&account_actor)
        .bind::<Text, _>(format!("inventory-device-{namespace}"))
        .bind::<diesel::sql_types::Binary, _>(vec![1_u8])
        .bind::<Text, _>(format!("sha256:{:1<64}", namespace))
        .bind::<diesel::sql_types::Binary, _>(vec![0_u8; 33])
        .execute(&mut conn)
        .await
        .expect("insert KeyPackage source");
        sql_query(
            "INSERT INTO device_messages \
             (id, idempotency_key, sender, recipient, device_id, recipient_device_authorization, position, content) \
             VALUES ($1, $2, $3, $4, $5, '{}'::jsonb, 1, '{}'::jsonb)",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::new_v4())
        .bind::<Text, _>(format!("message-{namespace}"))
        .bind::<Text, _>(&account_actor)
        .bind::<Text, _>(&peer_actor)
        .bind::<Text, _>(format!("peer-device-{namespace}"))
        .execute(&mut conn)
        .await
        .expect("insert to-device source");
        sql_query(
            "INSERT INTO push_devices \
             (id, actor_id, device_id, device_authorization, push_gateway, push_key, payload) \
             VALUES ($1, $2, $3, '{}'::jsonb, $4, $5, $6)",
        )
        .bind::<Text, _>(format!("push-{namespace}"))
        .bind::<Text, _>(&account_actor)
        .bind::<Text, _>(format!("inventory-device-{namespace}"))
        .bind::<Text, _>("https://push.invalid/")
        .bind::<Text, _>(format!("push-key-{namespace}"))
        .bind::<Jsonb, _>(serde_json::json!({
            "account_id": account_id,
            "push_route_id": format!("route-{namespace}"),
            "push_target_id": format!("target-{namespace}")
        }))
        .execute(&mut conn)
        .await
        .expect("insert push-route source");
        sql_query(
            "INSERT INTO invite_locators \
             (locator_id, token_digest, subject_id, recipient_id, issued_at, expires_at, record_payload) \
             VALUES ($1, $2, $3, $4, $5, $6, '{}'::jsonb)",
        )
        .bind::<Text, _>(format!("locator-{namespace}"))
        .bind::<Text, _>(format!("token-{namespace}"))
        .bind::<Text, _>(&account_actor)
        .bind::<Text, _>(&peer_actor)
        .bind::<Timestamptz, _>(now)
        .bind::<Timestamptz, _>(now + chrono::Duration::hours(1))
        .execute(&mut conn)
        .await
        .expect("insert principal-locator source");

        let store = PgAccountStatusReplicaStore { pool };
        let observations = store
            .discover_affected_services(&account_id, &holder, now)
            .await
            .expect("discover closed source families");
        for source in [
            AccountStatusAffectedServiceSource::Session,
            AccountStatusAffectedServiceSource::Device,
            AccountStatusAffectedServiceSource::KeyPackage,
            AccountStatusAffectedServiceSource::ToDevice,
            AccountStatusAffectedServiceSource::PushRoute,
            AccountStatusAffectedServiceSource::PrincipalLocator,
        ] {
            assert!(observations.iter().any(|observation| {
                observation.source == source && observation.service_id == holder
            }));
        }
        for source in [
            AccountStatusAffectedServiceSource::Session,
            AccountStatusAffectedServiceSource::ToDevice,
            AccountStatusAffectedServiceSource::PrincipalLocator,
        ] {
            assert!(observations.iter().any(|observation| {
                observation.source == source && observation.service_id == peer
            }));
        }
    }

    #[tokio::test]
    async fn postgres_propagation_window_marks_incomplete_then_clears_after_late_acks() {
        let pool = test_pool().await;
        let store = PgAccountStatusReplicaStore { pool: pool.clone() };
        let record = propagation_record(&unique_namespace());
        let destination_a =
            arkret_wire::DidCoreId::new("ak:did_core:web:propagation-a.example").unwrap();
        let destination_b =
            arkret_wire::DidCoreId::new("ak:did_core:web:propagation-b.example").unwrap();
        let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let deadline = now + chrono::Duration::minutes(10);

        let scheduled = store
            .begin_propagation(
                &record,
                &[destination_a.clone(), destination_b.clone()],
                deadline,
                now,
            )
            .await
            .expect("freeze propagation targets");
        assert_eq!(
            scheduled.state,
            AccountStatusPropagationProjectionState::Scheduled
        );
        assert_eq!(scheduled.pending_destination_count, 2);

        let replay = store
            .begin_propagation(
                &record,
                &[destination_b.clone(), destination_a.clone()],
                deadline + chrono::Duration::hours(1),
                now + chrono::Duration::seconds(1),
            )
            .await
            .expect("exact record replay returns frozen window");
        assert_eq!(replay.deadline_at, deadline);

        let timed_out = store
            .current_propagation_projection(
                &record.account_id,
                deadline + chrono::Duration::milliseconds(1),
            )
            .await
            .expect("promote overdue projection")
            .expect("projection exists");
        assert!(timed_out.became_incomplete);
        assert_eq!(
            timed_out.projection.state,
            AccountStatusPropagationProjectionState::Incomplete
        );

        let first_ack = store
            .acknowledge_propagation_destination(
                &record.account_status_record_id,
                &destination_a,
                deadline + chrono::Duration::seconds(1),
            )
            .await
            .expect("persist first late ack")
            .expect("target exists");
        assert_eq!(first_ack.projection.pending_destination_count, 1);
        assert!(!first_ack.became_complete);

        let final_ack = store
            .acknowledge_propagation_destination(
                &record.account_status_record_id,
                &destination_b,
                deadline + chrono::Duration::seconds(2),
            )
            .await
            .expect("persist final late ack")
            .expect("target exists");
        assert!(final_ack.became_complete);
        assert_eq!(
            final_ack.projection.state,
            AccountStatusPropagationProjectionState::Complete
        );
        assert_eq!(final_ack.projection.pending_destination_count, 0);

        let restarted = PgAccountStatusReplicaStore { pool };
        let durable = restarted
            .current_propagation_projection(
                &record.account_id,
                deadline + chrono::Duration::hours(1),
            )
            .await
            .expect("read projection after restart")
            .expect("projection exists");
        assert_eq!(
            durable.projection.state,
            AccountStatusPropagationProjectionState::Complete
        );
        assert!(!durable.became_complete);

        let direct_record = propagation_record(&unique_namespace());
        let direct_deadline = now + chrono::Duration::minutes(10);
        store
            .begin_propagation(
                &direct_record,
                std::slice::from_ref(&destination_a),
                direct_deadline,
                now,
            )
            .await
            .expect("freeze direct-late-ack target");
        let direct_late_ack = store
            .acknowledge_propagation_destination(
                &direct_record.account_status_record_id,
                &destination_a,
                direct_deadline + chrono::Duration::seconds(1),
            )
            .await
            .expect("persist direct late ack")
            .expect("direct target exists");
        assert!(direct_late_ack.became_incomplete);
        assert!(direct_late_ack.became_complete);
        assert_eq!(
            direct_late_ack.projection.state,
            AccountStatusPropagationProjectionState::Complete
        );
    }
}
