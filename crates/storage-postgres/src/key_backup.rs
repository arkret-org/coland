use diesel_async::AsyncConnection;

use super::{
    Binary, Integer, JsonPayloadRow, Jsonb, KeyBackupDeleteChallengeRecord, KeyBackupStore,
    Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool, QueryableByName,
    RunQueryDsl, Text, Timestamptz, Utc, Value, async_trait, ids, pg_conn, sql_query, sql_types,
};

#[derive(QueryableByName)]
struct KeyBackupDeleteChallengeRow {
    #[diesel(sql_type = Text)]
    challenge_id: String,
    #[diesel(sql_type = Text)]
    principal_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    station_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Text)]
    backup_id: String,
    #[diesel(sql_type = Text)]
    request_id: String,
    #[diesel(sql_type = Jsonb)]
    challenge: Value,
    #[diesel(sql_type = Timestamptz)]
    issued_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<chrono::DateTime<Utc>>,
}

impl From<KeyBackupDeleteChallengeRow> for KeyBackupDeleteChallengeRecord {
    fn from(row: KeyBackupDeleteChallengeRow) -> Self {
        Self {
            challenge_id: row.challenge_id,
            account_id: arkret_wire::AccountId::new(row.principal_id, row.station_id),
            backup_id: row.backup_id,
            request_id: row.request_id,
            challenge: row.challenge,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            consumed_at: row.consumed_at,
        }
    }
}

const DELETE_CHALLENGE_COLUMNS: &str = "challenge_id, principal_id, station_id, backup_id, request_id, challenge, issued_at, expires_at, consumed_at";
/// SOL-02-004 — classify a `key_backups` INSERT failure. A unique violation on
/// `key_backups_series_seq_key` means a concurrent successor PUT already
/// claimed this `(actor_id, series_id, series_sequence)` tuple; surface it as a
/// [`PersistenceError::Conflict`] so the receive path can reject the loser of
/// the race with the §7.6 `series_seq_not_monotonic` wire code instead of a
/// generic 5xx. Every other diesel error stays a `Database` error.
fn map_key_backup_put_error(error: horme::Error) -> PersistenceError {
    use diesel::result::{DatabaseErrorKind, Error as DieselError};
    if let horme::Error::Query(DieselError::DatabaseError(
        DatabaseErrorKind::UniqueViolation,
        info,
    )) = &error
    {
        let constraint = info.constraint_name().unwrap_or_default();
        if constraint.is_empty() || constraint == "key_backups_series_seq_key" {
            return PersistenceError::Conflict(format!(
                "series_seq_not_monotonic: {}",
                info.message()
            ));
        }
    }
    PersistenceError::database(error)
}

/// Store one validated envelope inside a transaction the caller owns. The
/// series uniqueness constraint is the race guard; a lost race surfaces as
/// `series_seq_not_monotonic`.
pub(crate) async fn put_key_backup_in_connection(
    conn: &mut crate::AsyncPgConnection,
    backup_id: &str,
    payload: &Value,
) -> PersistenceResult<()> {
    let typed: arkret_models_crypto::KeyBackup =
        serde_json::from_value(payload.clone()).map_err(PersistenceError::database)?;
    typed
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    // `metadata` is generated from `payload` by the initial schema's closed
    // `backup_metadata` projection; no writer supplies it.
    let extract_str = |key: &str| -> Option<String> {
        payload
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    };
    let actor_id = payload
        .get("actor_id")
        .cloned()
        .ok_or_else(|| PersistenceError::database("key backup actor_id is missing"))
        .and_then(|value| {
            serde_json::from_value::<arkret_wire::ActorId>(value)
                .map_err(|_| PersistenceError::database("key backup actor_id is invalid"))
        })?
        .to_string();
    let device_id = extract_str("device_id");
    let scheme = extract_str("scheme").or_else(|| extract_str("algorithm"));
    let version: i32 = payload
        .get("version")
        .and_then(Value::as_i64)
        .map(|v| v.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
        .unwrap_or(0);
    // base64-decoded key material lives in `key_material_encrypted` if the
    // caller already provided raw bytes via a `bytes_b64` field. Otherwise
    // the encrypted material stays in the JSONB envelope.
    let key_material: Option<Vec<u8>> = payload
        .get("key_material_encrypted_b64")
        .and_then(Value::as_str)
        .and_then(|s| {
            use base64::Engine as _;
            use base64::engine::general_purpose::STANDARD;
            STANDARD.decode(s).ok()
        });
    sql_query(
        "INSERT INTO key_backups \
         (id, actor_id, device_id, scheme, version, key_material_encrypted, payload, created_at, last_accessed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NULL) \
         ON CONFLICT (id) DO UPDATE SET \
            actor_id = EXCLUDED.actor_id, \
            device_id = EXCLUDED.device_id, \
            scheme = EXCLUDED.scheme, \
            version = EXCLUDED.version, \
            key_material_encrypted = EXCLUDED.key_material_encrypted, \
            payload = EXCLUDED.payload",
    )
    .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(backup_id))
    .bind::<Text, _>(&actor_id)
    .bind::<Nullable<Text>, _>(&device_id)
    .bind::<Nullable<Text>, _>(&scheme)
    .bind::<Integer, _>(version)
    .bind::<Nullable<Binary>, _>(key_material.as_deref())
    .bind::<Jsonb, _>(payload)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(map_key_backup_put_error)
}

pub struct PgKeyBackupStore {
    pub pool: PgPool,
}
async fn list_page_in_connection(
    conn: &mut crate::AsyncPgConnection,
    query: &coland_storage::KeyBackupListQuery,
) -> PersistenceResult<coland_storage::KeyBackupListPage> {
    #[derive(QueryableByName)]
    struct PageRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        revision: i64,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        byte_limited: bool,
        #[diesel(sql_type = Jsonb)]
        payloads: Value,
    }
    if !(1..=201).contains(&query.limit) {
        return Err(PersistenceError::database(
            "backup storage page limit must be 1..201",
        ));
    }
    let actor = serde_json::from_str::<arkret_wire::ActorId>(&query.actor_id)
        .map_err(|_| PersistenceError::database("invalid backup page actor"))?
        .to_string();
    let after = query.after.as_ref();
    let row = sql_query(r#"
            WITH candidates AS MATERIALIZED (
                SELECT metadata, backup_kind, series_id, series_sequence, id FROM key_backups
                WHERE actor_id=$1 AND ($2::text IS NULL OR backup_kind=$2) AND ($3::text IS NULL OR series_id=$3)
                AND ($4::text IS NULL OR (backup_kind COLLATE "C",series_id COLLATE "C",series_sequence,id) >
                     ($4::text COLLATE "C",$5::text COLLATE "C",$6::bigint,$7::uuid))
                ORDER BY backup_kind COLLATE "C",series_id COLLATE "C",series_sequence,id LIMIT $8
            ), sized AS MATERIALIZED (
                SELECT *, SUM(octet_length(metadata::text)+1) OVER (
                    ORDER BY backup_kind COLLATE "C",series_id COLLATE "C",series_sequence,id
                    ROWS UNBOUNDED PRECEDING) AS running_bytes FROM candidates
            )
            SELECT COALESCE((SELECT revision FROM key_backup_list_revisions WHERE actor_id=$1),0)::bigint AS revision,
                EXISTS(SELECT 1 FROM sized WHERE running_bytes > 900000) AS byte_limited,
                COALESCE((SELECT jsonb_agg(metadata ORDER BY backup_kind COLLATE "C",series_id COLLATE "C",series_sequence,id)
                    FROM sized WHERE running_bytes <= 900000), '[]'::jsonb) AS payloads
        "#)
        .bind::<Text,_>(actor)
        .bind::<Nullable<Text>,_>(query.backup_kind.as_deref())
        .bind::<Nullable<Text>,_>(query.series_id.as_deref())
        .bind::<Nullable<Text>,_>(after.map(|p| p.backup_kind.as_str()))
        .bind::<Text,_>(after.map_or("", |p| p.series_id.as_str()))
        .bind::<diesel::sql_types::BigInt,_>(after.map_or(0, |p| p.series_sequence))
        .bind::<Text,_>(after.map_or("00000000-0000-0000-0000-000000000000", |p| p.backup_id.trim_start_matches("ak:backup:")))
        .bind::<diesel::sql_types::BigInt,_>(i64::from(query.limit))
        .get_result::<PageRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let payloads = serde_json::from_value(row.payloads).map_err(PersistenceError::database)?;
    Ok(coland_storage::KeyBackupListPage {
        revision: row.revision,
        byte_limited: row.byte_limited,
        payloads,
    })
}

#[async_trait]
impl KeyBackupStore for PgKeyBackupStore {
    async fn confirmed_list_page_for_account(
        &self,
        account_id: &arkret_wire::AccountId,
        query: &coland_storage::KeyBackupListQuery,
    ) -> PersistenceResult<coland_storage::ConfirmedKeyBackupListPage> {
        if query.actor_id != arkret_wire::ActorId::account(account_id.clone()).to_string() {
            return Err(PersistenceError::SchemaViolation(
                "KeyBackup page actor differs from authenticated account".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *conn)
                .await?;
            let active_series =
                crate::key_backup_current_states::confirmed_key_backup_pointer_in_connection(
                    conn, account_id,
                )
                .await?
                .ok_or_else(|| {
                    PersistenceError::SchemaViolation(
                        "KeyBackup list has no confirmed PCR cut".to_owned(),
                    )
                })?;
            let page = list_page_in_connection(conn, query).await?;
            Ok(coland_storage::ConfirmedKeyBackupListPage {
                active_series,
                page,
            })
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }

    async fn confirmed_list_page_for_device(
        &self,
        account_id: &arkret_wire::AccountId,
        device_id: &arkret_wire::DeviceId,
        now: chrono::DateTime<Utc>,
        query: &coland_storage::KeyBackupListQuery,
    ) -> PersistenceResult<coland_storage::ConfirmedKeyBackupListPage> {
        let expected_actor = arkret_wire::ActorId::account(account_id.clone()).to_string();
        if query.actor_id != expected_actor {
            return Err(PersistenceError::SchemaViolation(
                "KeyBackup page actor differs from authenticated account".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<coland_storage::ConfirmedKeyBackupListPage, crate::PgTransactionError, _>(
            async |conn| {
                sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                    .execute(&mut *conn)
                    .await?;
                let active_series = crate::key_backup_current_states::confirmed_key_backup_pointer_for_active_device_in_connection(
                    conn, account_id, device_id, now,
                )
                .await?
                .ok_or_else(|| PersistenceError::SchemaViolation(
                    "KeyBackup list has no confirmed PCR cut".to_owned(),
                ))?;
                let page = list_page_in_connection(conn, query).await?;
                Ok(coland_storage::ConfirmedKeyBackupListPage { active_series, page })
            },
        )
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }

    async fn commit_active_series_pointer(
        &self,
        write: coland_storage::KeyBackupActiveSeriesCommitWrite,
    ) -> PersistenceResult<coland_storage::KeyBackupActiveSeriesCommitOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<coland_storage::KeyBackupActiveSeriesCommitOutcome, crate::PgTransactionError, _>(
            async |conn| {
                // An active-series Event a SecurityRotation reserved moves the
                // pointer only through that rotation's switch step, after its
                // replacement material is accepted (security-transactions §3).
                crate::security_transactions::refuse_rotation_reserved_pointer_in_connection(
                    conn,
                    &write.commit.event.event_id,
                )
                .await?;
                crate::key_backup_current_states::commit_key_backup_pointer_unit_in_connection(
                    conn, &write,
                )
                .await
            },
        )
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }

    async fn confirmed_active_series_for_device(
        &self,
        account_id: &arkret_wire::AccountId,
        device_id: &arkret_wire::DeviceId,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Option<arkret_models_crypto::BackupActiveSeriesState>> {
        crate::key_backup_current_states::confirmed_key_backup_pointer_for_active_device(
            &self.pool, account_id, device_id, now,
        )
        .await
    }

    async fn confirmed_active_series(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<arkret_models_crypto::BackupActiveSeriesState>> {
        crate::key_backup_current_states::confirmed_key_backup_pointer(&self.pool, account_id).await
    }
    async fn confirmed_active_series_basis(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<coland_storage::ConfirmedKeyBackupAuthorityBasis>> {
        crate::key_backup_current_states::confirmed_key_backup_pointer_basis(&self.pool, account_id)
            .await
    }
    async fn issue_unlock_challenge(
        &self,
        challenge: Value,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Value> {
        self.issue_unlock(challenge, now).await
    }
    async fn reserve_recovery_unlock_attempt(
        &self,
        authority_id: &str,
        holder: &str,
        request_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        self.reserve_recovery_attempt(authority_id, holder, request_digest, now)
            .await
    }
    async fn unlock_challenge(&self, authority_id: &str) -> PersistenceResult<Option<Value>> {
        self.read_unlock(authority_id).await
    }
    async fn consume_unlock(
        &self,
        command: coland_storage::KeyBackupUnlockCommand<'_>,
    ) -> PersistenceResult<Value> {
        self.consume_unlock_entry(command).await
    }
    async fn put(&self, backup_id: String, payload: Value) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        put_key_backup_in_connection(&mut conn, &backup_id, &payload).await
    }

    async fn get(&self, backup_id: &str) -> PersistenceResult<Option<Value>> {
        let mut conn = crate::pg_db(&self.pool);
        // last_accessed_at side-effect on read is informational; failure here
        // must not crash the get path.
        let _ = sql_query("UPDATE key_backups SET last_accessed_at = NOW() WHERE id = $1")
            .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(backup_id))
            .execute(&mut conn)
            .await;
        sql_query("SELECT payload FROM key_backups WHERE id = $1")
            .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(backup_id))
            .get_result::<JsonPayloadRow>(&mut conn)
            .await
            .optional()
            .map(|row| row.map(|r| r.payload))
            .map_err(PersistenceError::database)
    }

    async fn delete(&self, backup_id: &str) -> PersistenceResult<bool> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM key_backups WHERE id = $1")
            .bind::<sql_types::Uuid, _>(ids::typed_uuid_part_expect_internal(backup_id))
            .execute(&mut conn)
            .await
            .map(|n| n > 0)
            .map_err(PersistenceError::database)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("SELECT payload FROM key_backups ORDER BY created_at ASC, id ASC")
            .load::<JsonPayloadRow>(&mut conn)
            .await
            .map(|rows| rows.into_iter().map(|r| r.payload).collect())
            .map_err(PersistenceError::database)
    }

    async fn list_for_actor(&self, actor_id: &str) -> PersistenceResult<Vec<Value>> {
        let actor_id = serde_json::from_str::<arkret_wire::ActorId>(actor_id)
            .map_err(|_| PersistenceError::database("key backup actor selector is invalid"))?
            .to_string();
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT payload FROM key_backups WHERE actor_id = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind::<Text, _>(actor_id)
        .load::<JsonPayloadRow>(&mut conn)
        .await
        .map(|rows| rows.into_iter().map(|r| r.payload).collect())
        .map_err(PersistenceError::database)
    }

    async fn list_page(
        &self,
        query: &coland_storage::KeyBackupListQuery,
    ) -> PersistenceResult<coland_storage::KeyBackupListPage> {
        let mut conn = pg_conn(&self.pool).await?;
        list_page_in_connection(&mut conn, query).await
    }

    async fn issue_delete_challenge(
        &self,
        record: KeyBackupDeleteChallengeRecord,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<KeyBackupDeleteChallengeRecord> {
        let mut conn = crate::pg_db(&self.pool);
        // The row is unique on `(principal_id, station_id, backup_id, request_id)`, and the
        // `DO UPDATE ... WHERE` guard only replaces it once the held challenge
        // is consumed or expired. So this statement mints a challenge exactly
        // when §7.8.1 says a new one is due, and returns no row exactly when a
        // still-valid one is held.
        let issued = sql_query(format!(
            "INSERT INTO key_backup_delete_challenges ({DELETE_CHALLENGE_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL) ON CONFLICT (principal_id, station_id, backup_id, request_id) DO UPDATE SET challenge_id = EXCLUDED.challenge_id, challenge = EXCLUDED.challenge, issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at, consumed_at = NULL WHERE key_backup_delete_challenges.consumed_at IS NOT NULL OR key_backup_delete_challenges.expires_at <= $9 RETURNING {DELETE_CHALLENGE_COLUMNS}"
        ))
        .bind::<Text, _>(&record.challenge_id)
        .bind::<Text, _>(&record.account_id.principal_id)
        .bind::<Text, _>(&record.account_id.station_id)
        .bind::<Text, _>(&record.backup_id)
        .bind::<Text, _>(&record.request_id)
        .bind::<Jsonb, _>(&record.challenge)
        .bind::<Timestamptz, _>(record.issued_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .bind::<Timestamptz, _>(now)
        .get_result::<KeyBackupDeleteChallengeRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if let Some(issued) = issued {
            return Ok(KeyBackupDeleteChallengeRecord::from(issued));
        }
        // No row came back, so a still-valid challenge is held for this triple.
        // Returning it is the contract, not an error: §7.8.1 requires the same
        // `request_id` to keep receiving the same challenge while it is valid,
        // so a client retrying the issue call does not invalidate the challenge
        // it is already signing.
        sql_query(format!(
            "SELECT {DELETE_CHALLENGE_COLUMNS} FROM key_backup_delete_challenges WHERE principal_id = $1 AND station_id = $2 AND backup_id = $3 AND request_id = $4"
        ))
        .bind::<Text, _>(&record.account_id.principal_id)
        .bind::<Text, _>(&record.account_id.station_id)
        .bind::<Text, _>(&record.backup_id)
        .bind::<Text, _>(&record.request_id)
        .get_result::<KeyBackupDeleteChallengeRow>(&mut conn)
        .await
        .map(KeyBackupDeleteChallengeRecord::from)
        .map_err(PersistenceError::database)
    }

    async fn delete_challenge(
        &self,
        challenge_id: &str,
    ) -> PersistenceResult<Option<KeyBackupDeleteChallengeRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(format!(
            "SELECT {DELETE_CHALLENGE_COLUMNS} FROM key_backup_delete_challenges              WHERE challenge_id = $1"
        ))
        .bind::<Text, _>(challenge_id)
        .get_result::<KeyBackupDeleteChallengeRow>(&mut conn)
        .await
        .optional()
        .map(|row| row.map(KeyBackupDeleteChallengeRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn consume_delete_challenge(
        &self,
        gate: &coland_storage::KeyBackupDeleteGate,
        challenge_id: &str,
        backup: Value,
        recovery_session_id: Option<&str>,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        use diesel_async::AsyncConnection;
        conn.transaction::<_,super::PgTransactionError,_>(async move |conn| {
            super::key_backup_unlock::recheck_pointer_basis(conn,&gate.basis,&gate.quorum_devices,None).await?;
            if recovery_session_id.is_none() {
                let expected=gate.expected_policy.as_ref().ok_or_else(||PersistenceError::Conflict("device quorum policy gate required".into()))?;
                if gate.quorum_devices.is_empty() {return Err(PersistenceError::Conflict("device quorum current gates required".into()).into());}
                let account=&backup["actor_id"]["account_id"];
                let canonical=arkret_canonical::canonical_json_string(account).map_err(PersistenceError::database)?;
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))").bind::<Text,_>(format!("recovery-policy:{canonical}")).execute(&mut *conn).await.map_err(PersistenceError::database)?;
                let current=sql_query("SELECT p.raw_payload AS payload FROM recovery_policies p JOIN policy_current_states c ON c.policy_id=('ak:policy:' || p.id::text) AND c.current_commit_id=(p.acceptance_basis #>> '{}') AND c.value=p.raw_payload WHERE p.principal_id=$1 AND p.station_id=$2 ORDER BY p.version DESC LIMIT 1 FOR SHARE OF p")
                    .bind::<Text,_>(account["principal_id"].as_str().unwrap_or_default()).bind::<Text,_>(account["station_id"].as_str().unwrap_or_default())
                    .get_result::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?.payload;
                let now=chrono::Utc::now();
                if &current!=expected {return Err(PersistenceError::Conflict("device quorum policy changed".into()).into());}
                super::key_backup_unlock::ensure_policy_payload_active(&current, now)?;
            }
            if let Some(id)=recovery_session_id {
                super::key_backup_unlock::lock_recovery_policy_for_session(conn,id,now).await?;
                let now=chrono::Utc::now();
                let session=sql_query("SELECT to_jsonb(s) AS payload FROM recovery_sessions s WHERE id=$1 AND state='verified' AND expires_at>$2 AND transaction_id IS NULL FOR SHARE")
                    .bind::<sql_types::Uuid,_>(ids::typed_uuid_part_expect_internal(id)).bind::<Timestamptz,_>(now)
                    .get_result::<JsonPayloadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
                    .ok_or_else(||PersistenceError::Conflict("recovery session is no longer available".into()))?.payload;
                let account=&backup["actor_id"]["account_id"];
                if session["principal_id"]!=account["principal_id"] || session["station_id"]!=account["station_id"] {
                    return Err(PersistenceError::Conflict("recovery delete account mismatch".into()).into());
                }
            }
            let now=chrono::Utc::now();
            let row=sql_query(format!("SELECT {DELETE_CHALLENGE_COLUMNS} FROM key_backup_delete_challenges WHERE challenge_id=$1 AND consumed_at IS NULL AND expires_at>$2 FOR UPDATE"))
                .bind::<Text,_>(challenge_id).bind::<Timestamptz,_>(now)
                .get_result::<KeyBackupDeleteChallengeRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            let Some(row)=row else{return Ok(false)};
            if backup["backup_id"].as_str()!=Some(row.backup_id.as_str()) || backup["actor_id"]["account_id"]!=serde_json::json!({"principal_id":row.principal_id,"station_id":row.station_id}) {
                return Err(PersistenceError::Conflict("delete challenge backup binding mismatch".into()).into());
            }
            let deleted=sql_query("DELETE FROM key_backups WHERE id=$1 AND payload=$2")
                .bind::<sql_types::Uuid,_>(ids::typed_uuid_part_expect_internal(&row.backup_id)).bind::<Jsonb,_>(&backup)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            if deleted!=1 {return Err(PersistenceError::Conflict("backup changed before deletion".into()).into());}
            sql_query("UPDATE key_backup_delete_challenges SET consumed_at=$2 WHERE challenge_id=$1")
                .bind::<Text,_>(challenge_id).bind::<Timestamptz,_>(now)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            Ok(true)
        }).await.map_err(super::PgTransactionError::into_persistence)
    }

    async fn prune_expired_delete_challenges(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<usize> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM key_backup_delete_challenges WHERE expires_at <= $1")
            .bind::<Timestamptz, _>(now)
            .execute(&mut conn)
            .await
            .map_err(PersistenceError::database)
    }
}
