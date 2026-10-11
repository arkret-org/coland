use coland_storage::AccountPk;

use super::{
    AccountDataCasResult, AccountDataChangeRecord, AccountDataRecord, AccountDataStore,
    AccountLifecycleRecord, AccountLifecycleStore, AccountLocalpartRecord, AccountLocalpartStore,
    AccountRecord, AccountStore, AsyncConnection, BigInt, BlobRef, Bool, Jsonb, Nullable,
    OptionalExtension, PersistenceError, PersistenceResult, PgPool, QueryableByName, RunQueryDsl,
    Text, Timestamptz, Uuid, Value, account_with_primary_localpart_select, async_trait, ids,
    pg_conn, sql_query, sql_types,
};
pub struct PgAccountStore {
    pub pool: PgPool,
}
#[async_trait]
impl AccountStore for PgAccountStore {
    async fn get(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<AccountRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(account_with_primary_localpart_select(
            "WHERE a.station_id = $1 AND a.principal_id = $2",
        ))
        .bind::<Text, _>(account_id.station_id.as_str())
        .bind::<Text, _>(account_id.principal_id.as_str())
        .get_result::<AccountRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(AccountRecord::try_from).transpose()
    }

    async fn get_by_pk(&self, account_pk: AccountPk) -> PersistenceResult<Option<AccountRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(account_with_primary_localpart_select("WHERE a.pk = $1"))
            .bind::<BigInt, _>(account_pk.get())
            .get_result::<AccountRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
        row.map(AccountRecord::try_from).transpose()
    }

    async fn put(&self, record: &AccountRecord) -> PersistenceResult<AccountPk> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let payload = serde_json::json!({
            "bio": record.bio,
            "avatar_blob_ref": record.avatar_blob_ref,
        });
        let row = sql_query(
            "INSERT INTO accounts (principal_id, station_id, display_name, payload, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $5) \
             ON CONFLICT (station_id, principal_id) DO UPDATE SET \
             display_name = EXCLUDED.display_name, payload = EXCLUDED.payload, updated_at = NOW() \
             RETURNING pk",
        )
        .bind::<Text, _>(record.principal_id.as_str())
        .bind::<Text, _>(record.station_id.as_str())
        .bind::<Nullable<Text>, _>(&record.display_name)
        .bind::<Jsonb, _>(&payload)
        .bind::<Timestamptz, _>(record.created_at)
        .get_result::<AccountIdRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;

        // The account's inception on this Station is the only moment at which
        // an unbroken authoring interval can start, so the anchor is written
        // here and never refreshed: a later profile update is not a new
        // inception, and re-stamping one would erase a recorded break.
        sql_query(
            "INSERT INTO account_authoring_continuity (principal_id, station_id, inception_at) \
             VALUES ($1, $2, $3) ON CONFLICT (principal_id, station_id) DO NOTHING",
        )
        .bind::<Text, _>(record.principal_id.as_str())
        .bind::<Text, _>(record.station_id.as_str())
        .bind::<Timestamptz, _>(record.created_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;

        if record.localpart.trim().is_empty() {
            sql_query("DELETE FROM account_localparts WHERE account_pk = $1")
                .bind::<BigInt, _>(row.pk)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
        } else {
            sql_query(
                "UPDATE account_localparts SET is_primary = false, updated_at = NOW() \
                 WHERE account_pk = $1 AND localpart <> $2",
            )
            .bind::<BigInt, _>(row.pk)
            .bind::<Text, _>(&record.localpart)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            let assigned = sql_query(
                "INSERT INTO account_localparts \
                 (id, account_pk, localpart, is_primary, created_at, updated_at) \
                 VALUES ($1, $2, $3, true, $4, $4) \
                 ON CONFLICT (localpart) DO UPDATE SET \
                 account_pk = EXCLUDED.account_pk, is_primary = true, updated_at = NOW() \
                 WHERE account_localparts.account_pk = EXCLUDED.account_pk \
                 RETURNING localpart",
            )
            .bind::<sql_types::Uuid, _>(Uuid::now_v7())
            .bind::<BigInt, _>(row.pk)
            .bind::<Text, _>(&record.localpart)
            .bind::<Timestamptz, _>(record.created_at)
            .get_result::<LocalpartOnlyRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            let assigned_localpart = assigned.map(|row| row.localpart);
            if assigned_localpart.is_none() {
                return Err(PersistenceError::Conflict(format!(
                    "localpart `{}` is already assigned",
                    record.localpart
                )));
            }
        }
        Ok(AccountPk(row.pk))
    }

    async fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(account_with_primary_localpart_select(
            "ORDER BY a.station_id, a.principal_id",
        ))
        .load::<AccountRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(AccountRecord::try_from).collect()
    }

    async fn delete(&self, account_id: &arkret_wire::AccountId) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM accounts WHERE station_id = $1 AND principal_id = $2")
            .bind::<Text, _>(account_id.station_id.as_str())
            .bind::<Text, _>(account_id.principal_id.as_str())
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }

    async fn authoring_record_is_continuous(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT (broken_at IS NULL) AS continuous FROM account_authoring_continuity \
             WHERE principal_id = $1 AND station_id = $2",
        )
        .bind::<Text, _>(account_id.principal_id.as_str())
        .bind::<Text, _>(account_id.station_id.as_str())
        .get_result::<ContinuityRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        // A missing anchor is not continuity: it is the case this Station
        // cannot decide, and section 5.3.4 fails those closed.
        Ok(row.is_some_and(|row| row.continuous))
    }
}
pub struct PgAccountLocalpartStore {
    pub pool: PgPool,
}
#[async_trait]
impl AccountLocalpartStore for PgAccountLocalpartStore {
    async fn list_for_account(
        &self,
        account_pk: AccountPk,
    ) -> PersistenceResult<Vec<AccountLocalpartRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT lp.id, lp.account_pk, lp.localpart, lp.is_primary, lp.created_at, lp.updated_at \
             FROM account_localparts lp WHERE lp.account_pk = $1 \
             ORDER BY lp.is_primary DESC, lp.localpart ASC",
        )
        .bind::<BigInt, _>(account_pk.get())
        .load::<AccountLocalpartRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(AccountLocalpartRecord::try_from)
            .collect()
    }

    async fn owner_of(&self, localpart: &str) -> PersistenceResult<Option<AccountLocalpartRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT lp.id, lp.account_pk, lp.localpart, lp.is_primary, lp.created_at, lp.updated_at \
             FROM account_localparts lp WHERE lp.localpart = $1",
        )
        .bind::<Text, _>(localpart)
        .get_result::<AccountLocalpartRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(AccountLocalpartRecord::try_from).transpose()
    }

    async fn add(
        &self,
        account_pk: AccountPk,
        localpart: &str,
        primary: bool,
    ) -> PersistenceResult<AccountLocalpartRecord> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let existing_owner =
            sql_query("SELECT account_pk AS pk FROM account_localparts WHERE localpart = $1")
                .bind::<Text, _>(localpart)
                .get_result::<AccountIdRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
        if existing_owner.is_some_and(|owner| owner.pk != account_pk.get()) {
            return Err(PersistenceError::Conflict(format!(
                "localpart `{localpart}` is already assigned"
            )));
        }
        if primary {
            sql_query(
                "UPDATE account_localparts SET is_primary = false, updated_at = NOW() \
                 WHERE account_pk = $1",
            )
            .bind::<BigInt, _>(account_pk.get())
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        }
        let assigned = sql_query(
            "INSERT INTO account_localparts \
             (id, account_pk, localpart, is_primary, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, NOW(), NOW()) \
             ON CONFLICT (localpart) DO UPDATE SET \
             account_pk = EXCLUDED.account_pk, \
             is_primary = CASE WHEN EXCLUDED.is_primary THEN true ELSE account_localparts.is_primary END, \
             updated_at = NOW() \
             WHERE account_localparts.account_pk = EXCLUDED.account_pk \
             RETURNING id, account_pk, localpart, is_primary, created_at, updated_at",
        )
        .bind::<sql_types::Uuid, _>(Uuid::now_v7())
        .bind::<BigInt, _>(account_pk.get())
        .bind::<Text, _>(localpart)
        .bind::<Bool, _>(primary)
        .get_result::<AccountLocalpartRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        let assigned = assigned.ok_or_else(|| {
            PersistenceError::Conflict(format!("localpart `{localpart}` is already assigned"))
        })?;
        AccountLocalpartRecord::try_from(assigned)
    }

    async fn remove(&self, account_pk: AccountPk, localpart: &str) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "WITH inspected AS MATERIALIZED ( \
                 SELECT account_pk FROM account_localparts WHERE localpart = $2 \
             ), deleted AS ( \
                 DELETE FROM account_localparts WHERE account_pk = $1 AND localpart = $2 \
                 RETURNING account_pk \
             ) \
             SELECT CASE \
                 WHEN EXISTS (SELECT 1 FROM deleted) THEN 'removed' \
                 WHEN EXISTS (SELECT 1 FROM inspected WHERE account_pk <> $1) THEN 'conflict' \
                 ELSE 'absent' \
             END AS outcome",
        )
        .bind::<BigInt, _>(account_pk.get())
        .bind::<Text, _>(localpart)
        .get_result::<LocalpartRemovalOutcomeRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        match row.outcome.as_str() {
            "removed" | "absent" => Ok(()),
            "conflict" => Err(PersistenceError::Conflict(format!(
                "localpart `{localpart}` is assigned to another account"
            ))),
            outcome => Err(PersistenceError::Internal(format!(
                "unexpected localpart removal outcome `{outcome}`"
            ))),
        }
    }

    async fn clear_for_account(&self, account_pk: AccountPk) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM account_localparts WHERE account_pk = $1")
            .bind::<BigInt, _>(account_pk.get())
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }
}
pub struct PgAccountLifecycleStore {
    pub pool: PgPool,
}
#[async_trait]
impl AccountLifecycleStore for PgAccountLifecycleStore {
    async fn put(
        &self,
        account_pk: AccountPk,
        record: &AccountLifecycleRecord,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // Active public push handoff transactions hold FOR SHARE on this
        // account row. Take the conflicting lock before changing lifecycle
        // state, so an in-flight active intent or receipt cannot straddle a
        // completed deactivation transition.
        let written = sql_query(
            "WITH locked_account AS MATERIALIZED ( \
                 SELECT pk FROM accounts WHERE pk = $1 FOR UPDATE \
             ) INSERT INTO account_lifecycle \
             (account_pk, state, reason, changed_by, changed_at) \
             SELECT pk, $2, $3, $4, $5 FROM locked_account WHERE true \
             ON CONFLICT (account_pk) DO UPDATE SET \
               state = EXCLUDED.state, \
               reason = EXCLUDED.reason, \
               changed_by = EXCLUDED.changed_by, \
               changed_at = EXCLUDED.changed_at",
        )
        .bind::<BigInt, _>(account_pk.get())
        .bind::<Text, _>(&record.state)
        .bind::<Nullable<Text>, _>(&record.reason)
        .bind::<Nullable<Jsonb>, _>(
            record
                .changed_by
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|error| PersistenceError::database(format!("changed_by JSON: {error}")))?,
        )
        .bind::<Timestamptz, _>(record.changed_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if written != 1 {
            return Err(PersistenceError::NotFound(
                "account lifecycle account".to_owned(),
            ));
        }
        Ok(())
    }

    async fn delete(&self, account_pk: AccountPk) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM account_lifecycle WHERE account_pk = $1")
            .bind::<BigInt, _>(account_pk.get())
            .execute(&mut *conn)
            .await
            .map(|_| ())
            .map_err(PersistenceError::database)
    }

    async fn snapshot_all(
        &self,
    ) -> PersistenceResult<Vec<(arkret_wire::AccountId, AccountLifecycleRecord)>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT a.principal_id, a.station_id, l.state, l.reason, \
                    l.changed_by, l.changed_at \
             FROM account_lifecycle l \
             JOIN accounts a ON a.pk = l.account_pk \
             ORDER BY a.station_id, a.principal_id",
        )
        .load::<AccountLifecycleRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                let changed_by = row
                    .changed_by
                    .map(serde_json::from_value::<arkret_wire::ActorId>)
                    .transpose()
                    .map_err(|error| {
                        PersistenceError::database(format!("stored changed_by JSON: {error}"))
                    })?;
                Ok((
                    arkret_wire::AccountId::new(row.principal_id, row.station_id),
                    AccountLifecycleRecord {
                        state: row.state,
                        reason: row.reason,
                        changed_by,
                        changed_at: row.changed_at,
                    },
                ))
            })
            .collect()
    }
}
pub struct PgAccountDataStore {
    pub pool: PgPool,
}
#[async_trait]
impl AccountDataStore for PgAccountDataStore {
    async fn get(
        &self,
        actor: &str,
        account_data_key: &str,
    ) -> PersistenceResult<Option<AccountDataRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT actor_id AS actor, account_data_key, revision, payload, tombstone, updated_at \
             FROM account_datas WHERE actor_id = $1 AND account_data_key = $2 AND account_data_source_current(actor_id,account_data_key)",
        )
        .bind::<Text, _>(actor)
        .bind::<Text, _>(account_data_key)
        .get_result::<AccountDataRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AccountDataRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn compare_and_set(
        &self,
        record: &AccountDataRecord,
        expected_revision: u64,
    ) -> PersistenceResult<AccountDataCasResult> {
        self.compare_and_set_inner(record, expected_revision).await
    }
    async fn admit_actor_private_event(
        &self,
        admission: &coland_storage::ActorPrivateAccountDataAdmission,
    ) -> PersistenceResult<coland_storage::ActorPrivateAccountDataOutcome> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, crate::PgTransactionError, _>(async move |conn| {
            crate::unit_of_work::admit_actor_private_account_data_in_connection(conn, admission)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }

    async fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<AccountDataRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT actor_id AS actor, account_data_key, revision, payload, tombstone, updated_at \
             FROM account_datas WHERE actor_id = $1 AND tombstone = FALSE AND account_data_source_current(actor_id,account_data_key) \
             ORDER BY account_data_key",
        )
        .bind::<Text, _>(actor)
        .load::<AccountDataRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(AccountDataRecord::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn changes_after(
        &self,
        actor: &str,
        position: u64,
    ) -> PersistenceResult<Vec<AccountDataChangeRecord>> {
        let position = i64::try_from(position).map_err(|_| {
            PersistenceError::Conflict(
                "account_data change position exceeds i64 storage range".to_owned(),
            )
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT position, actor_id AS actor, account_data_key, revision, payload, tombstone, updated_at \
             FROM account_data_changes WHERE actor_id = $1 AND position > $2 AND account_data_source_current(actor_id,account_data_key) ORDER BY position",
        )
        .bind::<Text, _>(actor)
        .bind::<BigInt, _>(position)
        .load::<AccountDataChangeRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(AccountDataChangeRecord::try_from)
        .collect()
    }

    async fn latest_change_position(&self, actor: &str) -> PersistenceResult<u64> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT COALESCE(latest_position, 0) AS position \
             FROM account_data_change_retention WHERE actor_id = $1 \
             UNION ALL SELECT 0 WHERE NOT EXISTS ( \
                 SELECT 1 FROM account_data_change_retention WHERE actor_id = $1 \
             ) LIMIT 1",
        )
        .bind::<Text, _>(actor)
        .get_result::<AccountDataPositionRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        u64::try_from(row.position).map_err(|_| {
            PersistenceError::Internal("negative account_data change position".to_owned())
        })
    }

    async fn snapshot_for_actor(
        &self,
        actor: &str,
    ) -> PersistenceResult<(Vec<AccountDataRecord>, u64)> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "WITH current_position AS ( \
                 SELECT COALESCE(latest_position, 0) AS position \
                 FROM account_data_change_retention WHERE actor_id = $1 \
                 UNION ALL SELECT 0 WHERE NOT EXISTS ( \
                     SELECT 1 FROM account_data_change_retention WHERE actor_id = $1 \
                 ) LIMIT 1 \
             ), live_rows AS ( \
                 SELECT actor_id AS actor, account_data_key, revision, payload, tombstone, updated_at \
                 FROM account_datas WHERE actor_id = $1 AND tombstone = FALSE AND account_data_source_current(actor_id,account_data_key) \
             ) \
             SELECT current_position.position, live_rows.actor, live_rows.account_data_key, \
                    live_rows.revision, live_rows.payload, live_rows.tombstone, live_rows.updated_at \
             FROM current_position LEFT JOIN live_rows ON TRUE \
             ORDER BY live_rows.account_data_key",
        )
        .bind::<Text, _>(actor)
        .load::<AccountDataSnapshotRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let position = rows.as_slice().first().map_or(0, |row| row.position);
        let position = u64::try_from(position).map_err(|_| {
            PersistenceError::Internal("negative account_data change position".to_owned())
        })?;
        let entries = rows
            .into_iter()
            .filter_map(AccountDataSnapshotRow::into_record)
            .collect::<PersistenceResult<Vec<_>>>()?;
        Ok((entries, position))
    }

    async fn change_position_is_replayable(
        &self,
        actor: &str,
        position: u64,
    ) -> PersistenceResult<bool> {
        let position = i64::try_from(position).map_err(|_| {
            PersistenceError::Conflict(
                "account_data change position exceeds i64 storage range".to_owned(),
            )
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT COALESCE(retained_through_position, 0) AS position \
             FROM account_data_change_retention WHERE actor_id = $1 \
             UNION ALL SELECT 0 WHERE NOT EXISTS ( \
                 SELECT 1 FROM account_data_change_retention WHERE actor_id = $1 \
             ) LIMIT 1",
        )
        .bind::<Text, _>(actor)
        .get_result::<AccountDataPositionRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(position >= row.position)
    }

    async fn prune_changes_before(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<u64> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let row = sql_query(
            "WITH deleted AS ( \
                 DELETE FROM account_data_changes WHERE updated_at < $1 \
                 RETURNING actor_id, position \
             ), floors AS ( \
                 SELECT actor_id, MAX(position) AS retained_through_position, COUNT(*) AS deleted_count \
                 FROM deleted GROUP BY actor_id \
             ), retention AS ( \
                 INSERT INTO account_data_change_retention \
                    (actor_id, latest_position, retained_through_position, updated_at) \
                 SELECT actor_id, retained_through_position, retained_through_position, now() FROM floors \
                 ON CONFLICT (actor_id) DO UPDATE SET \
                    latest_position = GREATEST(account_data_change_retention.latest_position, EXCLUDED.latest_position), \
                    retained_through_position = GREATEST(account_data_change_retention.retained_through_position, EXCLUDED.retained_through_position), \
                    updated_at = EXCLUDED.updated_at \
                 RETURNING actor_id \
             ) \
             SELECT COALESCE(SUM(deleted_count), 0)::bigint AS position FROM floors \
             CROSS JOIN (SELECT COUNT(*) FROM retention) AS retention_count",
        )
        .bind::<Timestamptz, _>(cutoff)
        .get_result::<AccountDataPositionRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        u64::try_from(row.position).map_err(|_| {
            PersistenceError::Internal("negative pruned account_data change count".to_owned())
        })
    }
}

#[derive(QueryableByName)]
struct AccountDataChangeRow {
    #[diesel(sql_type = BigInt)]
    position: i64,
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    account_data_key: String,
    #[diesel(sql_type = BigInt)]
    revision: i64,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Bool)]
    tombstone: bool,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<AccountDataChangeRow> for AccountDataChangeRecord {
    type Error = PersistenceError;

    fn try_from(row: AccountDataChangeRow) -> Result<Self, Self::Error> {
        let position = u64::try_from(row.position).map_err(|_| {
            PersistenceError::Internal("negative account_data change position".to_owned())
        })?;
        let revision = u64::try_from(row.revision)
            .map_err(|_| PersistenceError::Internal("negative account_data revision".to_owned()))?;
        Ok(Self {
            position,
            record: AccountDataRecord {
                actor: row.actor,
                account_data_key: row.account_data_key,
                revision,
                payload: row.payload,
                tombstone: row.tombstone,
                updated_at: row.updated_at,
            },
        })
    }
}

#[derive(QueryableByName)]
struct AccountDataPositionRow {
    #[diesel(sql_type = BigInt)]
    position: i64,
}

#[derive(QueryableByName)]
struct AccountDataSnapshotRow {
    #[diesel(sql_type = BigInt)]
    position: i64,
    #[diesel(sql_type = Nullable<Text>)]
    actor: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    account_data_key: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    revision: Option<i64>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    payload: Option<Value>,
    #[diesel(sql_type = Nullable<Bool>)]
    tombstone: Option<bool>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl AccountDataSnapshotRow {
    fn into_record(self) -> Option<PersistenceResult<AccountDataRecord>> {
        let actor = self.actor?;
        let account_data_key = self.account_data_key?;
        let revision = self.revision?;
        let payload = self.payload?;
        let tombstone = self.tombstone?;
        let updated_at = self.updated_at?;
        Some(
            u64::try_from(revision)
                .map(|revision| AccountDataRecord {
                    actor,
                    account_data_key,
                    revision,
                    payload,
                    tombstone,
                    updated_at,
                })
                .map_err(|_| {
                    PersistenceError::Internal("negative account_data revision".to_owned())
                }),
        )
    }
}
#[derive(QueryableByName)]
struct AccountRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
    #[diesel(sql_type = Text)]
    principal_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Text)]
    station_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Text)]
    localpart: String,
    #[diesel(sql_type = Nullable<Text>)]
    display_name: Option<String>,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}
#[derive(QueryableByName)]
struct AccountIdRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}
#[derive(QueryableByName)]
struct ContinuityRow {
    #[diesel(sql_type = Bool)]
    continuous: bool,
}
#[derive(QueryableByName)]
struct AccountLocalpartRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = BigInt)]
    account_pk: i64,
    #[diesel(sql_type = Text)]
    localpart: String,
    #[diesel(sql_type = Bool)]
    is_primary: bool,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}
#[derive(QueryableByName)]
struct LocalpartOnlyRow {
    #[diesel(sql_type = Text)]
    localpart: String,
}
#[derive(QueryableByName)]
struct LocalpartRemovalOutcomeRow {
    #[diesel(sql_type = Text)]
    outcome: String,
}
#[derive(QueryableByName)]
struct AccountLifecycleRow {
    #[diesel(sql_type = Text)]
    principal_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Text)]
    station_id: arkret_wire::DidCoreId,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Text>)]
    reason: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    changed_by: Option<Value>,
    #[diesel(sql_type = Timestamptz)]
    changed_at: chrono::DateTime<chrono::Utc>,
}
impl TryFrom<AccountLocalpartRow> for AccountLocalpartRecord {
    type Error = PersistenceError;

    fn try_from(row: AccountLocalpartRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: ids::format_typed_uuid("account_localpart", &row.id),
            account_pk: AccountPk(row.account_pk),
            localpart: row.localpart,
            is_primary: row.is_primary,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}
impl TryFrom<AccountRow> for AccountRecord {
    type Error = PersistenceError;

    fn try_from(row: AccountRow) -> Result<Self, Self::Error> {
        Ok(Self {
            pk: AccountPk(row.pk),
            principal_id: row.principal_id,
            station_id: row.station_id,
            localpart: row.localpart,
            display_name: row.display_name,
            bio: row
                .payload
                .get("bio")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            avatar_blob_ref: row
                .payload
                .get("avatar_blob_ref")
                .and_then(Value::as_str)
                .and_then(|value| BlobRef::new(value.to_owned()).ok()),
            created_at: row.created_at,
        })
    }
}
#[derive(QueryableByName)]
struct AccountDataRow {
    #[diesel(sql_type = Text)]
    actor: String,
    #[diesel(sql_type = Text)]
    account_data_key: String,
    #[diesel(sql_type = BigInt)]
    revision: i64,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Bool)]
    tombstone: bool,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}
impl From<AccountDataRow> for AccountDataRecord {
    fn from(row: AccountDataRow) -> Self {
        Self {
            actor: row.actor,
            account_data_key: row.account_data_key,
            revision: u64::try_from(row.revision)
                .expect("account_data revision constraint guarantees non-negative values"),
            payload: row.payload,
            tombstone: row.tombstone,
            updated_at: row.updated_at,
        }
    }
}

impl PgAccountDataStore {
    async fn compare_and_set_inner(
        &self,
        record: &AccountDataRecord,
        expected_revision: u64,
    ) -> PersistenceResult<AccountDataCasResult> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        compare_account_data_in_transaction(&mut conn, record, expected_revision, None).await
    }
}
pub(crate) async fn compare_account_data_in_transaction(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &AccountDataRecord,
    expected_revision: u64,
    source_event_id: Option<&arkret_wire::EventId>,
) -> PersistenceResult<AccountDataCasResult> {
    let expected_revision = i64::try_from(expected_revision).map_err(|_| {
        PersistenceError::Conflict("account_data revision exceeds i64 storage range".to_owned())
    })?;
    let revision = i64::try_from(record.revision).map_err(|_| {
        PersistenceError::Conflict("account_data revision exceeds i64 storage range".to_owned())
    })?;
    if revision
        != expected_revision.checked_add(1).ok_or_else(|| {
            PersistenceError::Conflict("account_data revision exhausted".to_owned())
        })?
    {
        return Err(PersistenceError::Internal(
            "account_data record revision must equal expected_revision + 1".to_owned(),
        ));
    }
    let applied = sql_query(
            "WITH source AS MATERIALIZED ( SELECT e.envelope FROM actor_private_events e \
                 WHERE e.id=$9 AND e.actor_id=$2 AND e.kind='ak.account_data.set' \
                   AND e.envelope->'payload'->>'key'=$3 \
                   AND (e.envelope->'payload'->>'expected_server_revision')::bigint=$8 \
                   AND COALESCE((e.envelope->'payload'->>'tombstone')::boolean,FALSE)=$6 \
                   AND ($6 OR COALESCE(e.envelope->'payload'->'body',e.envelope->'payload'->'encrypted_payload')=$5) \
                   FOR SHARE OF e \
             ), updated AS ( \
                 UPDATE account_datas SET revision = $4, payload = $5, tombstone = $6, updated_at = $7 \
                 WHERE actor_id = $2 AND account_data_key = $3 AND revision = $8 AND ($9::bytea IS NULL OR EXISTS (SELECT 1 FROM source)) \
                 RETURNING actor_id AS actor, account_data_key, revision, payload, tombstone, updated_at \
             ), inserted AS ( \
                 INSERT INTO account_datas \
                    (id, actor_id, account_data_key, revision, payload, tombstone, updated_at) \
                 SELECT $1, $2, $3, $4, $5, $6, $7 \
                 WHERE $8 = 0 AND ($9::bytea IS NULL OR EXISTS (SELECT 1 FROM source)) AND NOT EXISTS ( \
                     SELECT 1 FROM account_datas WHERE actor_id = $2 AND account_data_key = $3 \
                 ) \
                 ON CONFLICT (actor_id, account_data_key) DO NOTHING \
                 RETURNING actor_id AS actor, account_data_key, revision, payload, tombstone, updated_at \
             ), applied AS ( \
                 SELECT * FROM updated UNION ALL SELECT * FROM inserted \
             ), changed AS ( \
                 INSERT INTO account_data_changes \
                    (actor_id, account_data_key, revision, payload, tombstone, updated_at) \
                 SELECT actor, account_data_key, revision, payload, tombstone, updated_at \
                 FROM applied \
                 RETURNING position \
             ), retention AS ( \
                 INSERT INTO account_data_change_retention \
                    (actor_id, latest_position, retained_through_position, updated_at) \
                 SELECT $2, position, 0, now() FROM changed \
                 ON CONFLICT (actor_id) DO UPDATE SET \
                    latest_position = GREATEST(account_data_change_retention.latest_position, EXCLUDED.latest_position), \
                    updated_at = EXCLUDED.updated_at \
                 RETURNING latest_position \
             ) \
             , published AS MATERIALIZED ( \
                 SELECT project_account_global_value($2,'account_data_events','event:'||$3, \
                    jsonb_build_object('source','event','value',source.envelope),$6) FROM applied CROSS JOIN source \
             ) SELECT applied.* FROM applied \
             CROSS JOIN (SELECT count(*) FROM retention) AS retention_count CROSS JOIN (SELECT count(*) FROM published) AS published_count",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.actor)
        .bind::<Text, _>(&record.account_data_key)
        .bind::<BigInt, _>(revision)
        .bind::<Jsonb, _>(&record.payload)
        .bind::<Bool, _>(record.tombstone)
        .bind::<Timestamptz, _>(record.updated_at)
        .bind::<BigInt, _>(expected_revision)
        .bind::<Nullable<diesel::sql_types::Binary>, _>(source_event_id.map(|id| id.token_bytes().to_vec()))
        .get_result::<AccountDataRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
    if let Some(applied) = applied {
        return Ok(AccountDataCasResult::Applied(applied.into()));
    }
    let current = sql_query("SELECT actor_id AS actor, account_data_key, revision, payload, tombstone, updated_at FROM account_datas WHERE actor_id=$1 AND account_data_key=$2 AND account_data_source_current(actor_id,account_data_key)")
            .bind::<Text,_>(&record.actor).bind::<Text,_>(&record.account_data_key)
            .get_result::<AccountDataRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.map(AccountDataRecord::from);
    Ok(AccountDataCasResult::Conflict(current))
}
