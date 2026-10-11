use super::{
    BigInt, CursorRevocation, Jsonb, Nullable, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, QueryableByName, RunQueryDsl, SyncCursorRecord, SyncCursorStore,
    Text, Timestamptz, Utc, Value, async_trait, pg_conn, sql_query, sql_types,
};
pub(crate) mod retention;
use coland_storage::RealmJoinDownload;
use diesel_async::AsyncConnection;
pub struct PgSyncCursorStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct RealmJoinDownloadRow {
    #[diesel(sql_type = Jsonb)]
    assembly: Value,
}
#[derive(QueryableByName)]
struct AccountWatermarksRow {
    #[diesel(sql_type = BigInt)]
    summary_revision: i64,
    #[diesel(sql_type = BigInt)]
    global_revision: i64,
}
#[derive(QueryableByName)]
struct GlobalReadRow {
    #[diesel(sql_type = Text)]
    item_key: String,
    #[diesel(sql_type = BigInt)]
    channel_position: i64,
    #[diesel(sql_type = BigInt)]
    revision: i64,
    #[diesel(sql_type = sql_types::Bool)]
    deleted: bool,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}
#[derive(QueryableByName)]
struct SummaryWatermarkRow {
    #[diesel(sql_type = BigInt)]
    revision: i64,
}
#[derive(QueryableByName)]
struct SummaryReadRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = BigInt)]
    revision: i64,
    #[diesel(sql_type = BigInt)]
    activity_position: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    valid_until: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    membership: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    title: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    default_strand_id: Option<String>,
    #[diesel(sql_type = sql_types::Bool)]
    invalidated: bool,
    #[diesel(sql_type = Nullable<Text>)]
    current_membership: Option<String>,
    #[diesel(sql_type = sql_types::Bool)]
    current_available: bool,
}
impl From<SummaryReadRow> for coland_storage::AccountSummaryVersion {
    fn from(row: SummaryReadRow) -> Self {
        Self {
            key: coland_storage::AccountSummaryKey {
                realm_id: row.realm_id,
                revision: row.revision,
                activity_position: row.activity_position,
            },
            valid_until: row.valid_until,
            membership: row.membership,
            title: row.title,
            default_strand_id: row.default_strand_id,
            invalidated: row.invalidated,
            current_membership: row.current_membership,
            current_available: row.current_available,
        }
    }
}

#[derive(QueryableByName)]
struct SyncCursorRow {
    #[diesel(sql_type = Text)]
    handle: String,
    #[diesel(sql_type = Nullable<Text>)]
    binding_subject: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    device_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    session_id: Option<String>,
    #[diesel(sql_type = Text)]
    service_id: arkret_identifiers::DidCoreId,
    #[diesel(sql_type = Nullable<Text>)]
    filter_digest: Option<String>,
    #[diesel(sql_type = Text)]
    purpose: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    positions: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    target: Option<Value>,
    #[diesel(sql_type = BigInt)]
    issued_at_ms: i64,
    #[diesel(sql_type = BigInt)]
    expires_at_ms: i64,
}
impl From<SyncCursorRow> for SyncCursorRecord {
    fn from(row: SyncCursorRow) -> Self {
        SyncCursorRecord {
            handle: row.handle,
            binding_subject: row.binding_subject,
            device_id: row.device_id,
            session_id: row.session_id,
            service_id: row.service_id,
            filter_digest: row.filter_digest,
            purpose: row.purpose,
            positions: row.positions,
            target: row.target,
            issued_at_ms: row.issued_at_ms,
            expires_at_ms: row.expires_at_ms,
        }
    }
}
#[async_trait]
impl SyncCursorStore for PgSyncCursorStore {
    async fn realm_join_download(&self, key: &str) -> PersistenceResult<Option<RealmJoinDownload>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT assembly FROM realm_join_downloads WHERE context_key = $1 AND expires_at > CURRENT_TIMESTAMP")
            .bind::<Text, _>(key)
            .get_result::<RealmJoinDownloadRow>(&mut *conn).await.optional()
            .map_err(PersistenceError::database)?
            .map(|row| serde_json::from_value(row.assembly).map_err(PersistenceError::database)).transpose()
    }

    async fn save_realm_join_download(
        &self,
        key: &str,
        assembly: &RealmJoinDownload,
    ) -> PersistenceResult<()> {
        if assembly.expires_at <= Utc::now() {
            return Err(PersistenceError::Conflict(
                "bootstrap download expired".into(),
            ));
        }
        let value = serde_json::to_value(assembly).map_err(PersistenceError::database)?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            sql_query("DELETE FROM realm_join_downloads WHERE expires_at <= CURRENT_TIMESTAMP")
                .execute(conn).await.map_err(PersistenceError::database)?;
            let written = sql_query(
                "INSERT INTO realm_join_downloads (context_key, assembly, expires_at) VALUES ($1, $2, $3) \
                 ON CONFLICT (context_key) DO UPDATE SET assembly = EXCLUDED.assembly \
                 WHERE (realm_join_downloads.assembly->'snapshot') = (EXCLUDED.assembly->'snapshot') \
                   AND ((realm_join_downloads.assembly->'items') <@ (EXCLUDED.assembly->'items') \
                        OR realm_join_downloads.assembly = EXCLUDED.assembly)"
            ).bind::<Text, _>(key).bind::<Jsonb, _>(&value)
                .bind::<Timestamptz, _>(assembly.expires_at)
                .execute(conn).await.map_err(PersistenceError::database)?;
            if written != 1 {
                return Err(PersistenceError::Conflict("bootstrap download context or progress changed".into()).into());
            }
            Ok(())
        }).await.map_err(crate::PgTransactionError::into_persistence)
    }

    async fn account_sync_watermarks(&self) -> PersistenceResult<(i64, i64)> {
        retention::freeze(&self.pool).await
    }
    async fn account_global_watermark(&self) -> PersistenceResult<i64> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT revision FROM account_global_clock WHERE singleton")
            .get_result::<SummaryWatermarkRow>(&mut *conn)
            .await
            .map(|row| row.revision)
            .map_err(PersistenceError::database)
    }
    async fn account_global_channel_position(
        &self,
        actor_key: &str,
        channel: &str,
        watermark: i64,
    ) -> PersistenceResult<i64> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT COALESCE(MAX(channel_position), 0)::bigint AS revision \
             FROM account_global_versions \
             WHERE actor_key = $1 AND channel = $2 AND revision <= $3",
        )
        .bind::<Text, _>(actor_key)
        .bind::<Text, _>(channel)
        .bind::<BigInt, _>(watermark)
        .get_result::<SummaryWatermarkRow>(&mut *conn)
        .await
        .map(|row| row.revision)
        .map_err(PersistenceError::database)
    }
    async fn account_global_page(
        &self,
        actor_key: &str,
        channel: &str,
        watermark: i64,
        after_key: &str,
        after_revision: Option<i64>,
        limit: usize,
    ) -> PersistenceResult<Vec<coland_storage::AccountGlobalVersion>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            retention::check(conn, None, Some(after_revision.unwrap_or(watermark))).await?;
            let result: PersistenceResult<_> = async {
        let rows = sql_query("WITH candidates AS MATERIALIZED (SELECT item_key,channel_position,revision,(deleted OR (channel='account_data_events' AND NOT EXISTS (SELECT 1 FROM actor_private_events e WHERE e.kind='ak.account_data.set' AND e.event_id=v.payload->'value'->>'event_id')) OR (channel='device_lists' AND NOT COALESCE(account_device_interest_visible(v.actor_key,v.item_key),FALSE))) AS deleted,CASE WHEN channel='account_data_events' AND NOT EXISTS (SELECT 1 FROM actor_private_events e WHERE e.kind='ak.account_data.set' AND e.event_id=v.payload->'value'->>'event_id') THEN jsonb_build_object('source','invalidated') ELSE payload END AS payload,CASE WHEN channel='notifications' THEN 1 ELSE octet_length(payload::text)+256 END AS byte_count FROM account_global_versions v WHERE actor_key=$1 AND channel=$2 AND revision<=$3 AND (($5::bigint IS NULL AND item_key>$4 AND (valid_until IS NULL OR valid_until>$3)) OR ($5::bigint IS NOT NULL AND revision>$5)) ORDER BY CASE WHEN $5::bigint IS NULL THEN item_key ELSE '' END, revision LIMIT $6), bounded AS (SELECT *,sum(byte_count) OVER (ORDER BY CASE WHEN $5::bigint IS NULL THEN item_key ELSE '' END, revision) AS total FROM candidates) SELECT item_key,channel_position,revision,deleted,CASE WHEN total>6291456 THEN jsonb_build_object('_budget_boundary',true,'_oversized',byte_count>6291456) ELSE payload END AS payload FROM bounded WHERE total-byte_count<=6291456 ORDER BY CASE WHEN $5::bigint IS NULL THEN item_key ELSE '' END,revision")
            .bind::<Text,_>(actor_key).bind::<Text,_>(channel).bind::<BigInt,_>(watermark).bind::<Text,_>(after_key).bind::<Nullable<BigInt>,_>(after_revision).bind::<BigInt,_>(limit.min(101) as i64)
            .load::<GlobalReadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                let mut payload = row.payload;
                if payload.get("_budget_boundary").is_some() {
                    return Ok(coland_storage::AccountGlobalVersion {
                        item_key: row.item_key,
                        channel_position: row.channel_position,
                        revision: row.revision,
                        deleted: row.deleted,
                        payload,
                    });
                }
                if channel == "notifications" {
                    payload = crate::notifications::global_notification_payload(payload)?;
                }
                Ok(coland_storage::AccountGlobalVersion {
                    item_key: row.item_key,
                    channel_position: row.channel_position,
                    revision: row.revision,
                    deleted: row.deleted,
                    payload,
                })
            })
            .collect()
            }.await;
            Ok(result?)
        }).await.map_err(crate::PgTransactionError::into_persistence)
    }

    async fn account_summary_watermark(&self) -> PersistenceResult<i64> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("SELECT revision FROM account_summary_clock WHERE singleton")
            .get_result::<SummaryWatermarkRow>(&mut *conn)
            .await
            .map(|row| row.revision)
            .map_err(PersistenceError::database)
    }

    async fn account_summary_page(
        &self,
        actor_key: &str,
        watermark: i64,
        after: Option<&coland_storage::AccountSummaryKey>,
        limit: usize,
    ) -> PersistenceResult<Vec<coland_storage::AccountSummaryVersion>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            retention::check(conn, Some(watermark), None).await?;
            let result: PersistenceResult<_> = async {
                // Limit the index scan itself before applying snapshot validity. Old
                // versions consume the scan budget and still advance the private key.
                sql_query(
                    "WITH candidates AS MATERIALIZED (
            SELECT * FROM account_summary_versions v WHERE actor_key = $1
              AND ($3::bigint IS NULL OR activity_position < $3
                OR (activity_position = $3 AND realm_id COLLATE \"C\" > $4 COLLATE \"C\")
                OR (activity_position = $3 AND realm_id = $4 AND revision < $5))
            ORDER BY activity_position DESC, realm_id COLLATE \"C\", revision DESC LIMIT $6
        ) SELECT v.realm_id, v.revision, v.activity_position, v.valid_until,
            v.membership, v.title, v.default_strand_id, v.invalidated,
            c.membership AS current_membership, COALESCE(c.available, FALSE) AS current_available
          FROM candidates v LEFT JOIN account_summary_current c
            ON c.actor_key = v.actor_key AND c.realm_id = v.realm_id
          WHERE $2 >= 0
          ORDER BY v.activity_position DESC, v.realm_id COLLATE \"C\", v.revision DESC",
                )
                .bind::<Text, _>(actor_key)
                .bind::<BigInt, _>(watermark)
                .bind::<Nullable<BigInt>, _>(after.map(|key| key.activity_position))
                .bind::<Nullable<Text>, _>(after.map(|key| key.realm_id.as_str()))
                .bind::<Nullable<BigInt>, _>(after.map(|key| key.revision))
                .bind::<BigInt, _>(limit.clamp(1, 200) as i64)
                .load::<SummaryReadRow>(&mut *conn)
                .await
                .map(|rows| rows.into_iter().map(Into::into).collect())
                .map_err(PersistenceError::database)
            }
            .await;
            Ok(result?)
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }

    async fn account_summary_changes(
        &self,
        actor_key: &str,
        after: i64,
        limit: usize,
    ) -> PersistenceResult<Vec<coland_storage::AccountSummaryVersion>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            retention::check(conn, Some(after), None).await?;
            let result: PersistenceResult<_> = async {
                sql_query(
                    "WITH candidates AS MATERIALIZED (
            SELECT * FROM account_summary_versions WHERE actor_key = $1 AND revision > $2
            ORDER BY revision, realm_id COLLATE \"C\" LIMIT $3
        ) SELECT v.realm_id, v.revision, v.activity_position, v.valid_until,
            v.membership, v.title, v.default_strand_id, v.invalidated,
            c.membership AS current_membership, COALESCE(c.available, FALSE) AS current_available
          FROM candidates v LEFT JOIN account_summary_current c
            ON c.actor_key = v.actor_key AND c.realm_id = v.realm_id
          ORDER BY v.revision, v.realm_id COLLATE \"C\"",
                )
                .bind::<Text, _>(actor_key)
                .bind::<BigInt, _>(after)
                .bind::<BigInt, _>(limit.clamp(1, 100) as i64)
                .load::<SummaryReadRow>(&mut *conn)
                .await
                .map(|rows| rows.into_iter().map(Into::into).collect())
                .map_err(PersistenceError::database)
            }
            .await;
            Ok(result?)
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }

    async fn get(&self, handle: &str) -> PersistenceResult<Option<SyncCursorRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT id AS handle, binding_subject, device_id, session_id, service_id, filter_digest, purpose, \
             positions, target, issued_at_ms, expires_at_ms \
             FROM sync_cursor_handles WHERE id = $1",
        )
        .bind::<Text, _>(handle)
        .get_result::<SyncCursorRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(SyncCursorRecord::from))
        .map_err(PersistenceError::database)
    }

    async fn upsert(&self, record: &SyncCursorRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let floors = retention::cursor_floors(record)?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            if let Some((summary, global)) = floors {
                retention::check(conn, Some(summary), Some(global)).await?;
            }
        // The entire issuance instance is immutable, including its expiry.
        let written = sql_query(
            "INSERT INTO sync_cursor_handles \
             (id, binding_subject, device_id, session_id, service_id, filter_digest, purpose, positions, target, issued_at_ms, expires_at_ms) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id \
             WHERE sync_cursor_handles.binding_subject IS NOT DISTINCT FROM EXCLUDED.binding_subject \
               AND sync_cursor_handles.device_id IS NOT DISTINCT FROM EXCLUDED.device_id \
               AND sync_cursor_handles.session_id IS NOT DISTINCT FROM EXCLUDED.session_id \
               AND sync_cursor_handles.service_id = EXCLUDED.service_id \
               AND sync_cursor_handles.filter_digest IS NOT DISTINCT FROM EXCLUDED.filter_digest \
               AND sync_cursor_handles.purpose = EXCLUDED.purpose \
               AND sync_cursor_handles.positions IS NOT DISTINCT FROM EXCLUDED.positions \
               AND sync_cursor_handles.target IS NOT DISTINCT FROM EXCLUDED.target \
               AND sync_cursor_handles.issued_at_ms = EXCLUDED.issued_at_ms \
               AND sync_cursor_handles.expires_at_ms = EXCLUDED.expires_at_ms",
        )
        .bind::<Text, _>(&record.handle)
        .bind::<Nullable<Text>, _>(&record.binding_subject)
        .bind::<Nullable<Text>, _>(&record.device_id)
        .bind::<Nullable<Text>, _>(&record.session_id)
        .bind::<Text, _>(&record.service_id)
        .bind::<Nullable<Text>, _>(&record.filter_digest)
        .bind::<Text, _>(&record.purpose)
        .bind::<Nullable<Jsonb>, _>(&record.positions)
        .bind::<Nullable<Jsonb>, _>(&record.target)
        .bind::<BigInt, _>(record.issued_at_ms)
        .bind::<BigInt, _>(record.expires_at_ms)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
            if written != 1 {
                return Err(PersistenceError::Conflict("cursor issuance is immutable".into()).into());
            }
            retention::save_cursor(conn, record, floors).await?;
            Ok(())
        }).await.map_err(crate::PgTransactionError::into_persistence)
    }

    async fn delete(&self, handle: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("DELETE FROM sync_cursor_handles WHERE id = $1")
            .bind::<Text, _>(handle)
            .execute(&mut *conn)
            .await
            .map(|rows| rows > 0)
            .map_err(PersistenceError::database)
    }

    async fn prune_expired(&self, now_ms: i64) -> PersistenceResult<usize> {
        retention::prune(&self.pool, now_ms).await
    }

    async fn record_revocation(&self, record: &CursorRevocation) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // Opportunistic TTL sweep on every write keeps the ledger bounded by
        // the stream TTL cap, independently of consumer-side reads.
        sql_query("DELETE FROM sync_cursor_revocations WHERE expires_at <= $1")
            .bind::<Timestamptz, _>(record.revoked_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO sync_cursor_revocations \
             (id, cursor_digest, account_id, device_id, session_id, scope, reason_code, revoked_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (cursor_digest, account_id, scope) DO NOTHING",
        )
        .bind::<sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&record.cursor_digest)
        .bind::<Jsonb, _>(serde_json::to_value(&record.account_id).map_err(PersistenceError::database)?)
        .bind::<Nullable<Text>, _>(&record.device_id)
        .bind::<Nullable<Text>, _>(&record.session_id)
        .bind::<Text, _>(&record.scope)
        .bind::<Text, _>(&record.reason_code)
        .bind::<Timestamptz, _>(record.revoked_at)
        .bind::<Timestamptz, _>(record.expires_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn active_revocations(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Vec<CursorRevocation>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT cursor_digest, account_id, device_id, session_id, scope, reason_code, revoked_at, expires_at \
             FROM sync_cursor_revocations WHERE expires_at > $1 \
             ORDER BY revoked_at ASC",
        )
        .bind::<Timestamptz, _>(now)
        .load::<CursorRevocationRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(CursorRevocation::from).collect())
    }
}
#[derive(QueryableByName)]
struct CursorRevocationRow {
    #[diesel(sql_type = Text)]
    cursor_digest: String,
    #[diesel(sql_type = Jsonb)]
    account_id: Value,
    #[diesel(sql_type = Nullable<Text>)]
    device_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    session_id: Option<String>,
    #[diesel(sql_type = Text)]
    scope: String,
    #[diesel(sql_type = Text)]
    reason_code: String,
    #[diesel(sql_type = Timestamptz)]
    revoked_at: chrono::DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<Utc>,
}
impl From<CursorRevocationRow> for CursorRevocation {
    fn from(row: CursorRevocationRow) -> Self {
        Self {
            cursor_digest: row.cursor_digest,
            account_id: serde_json::from_value(row.account_id)
                .expect("stored cursor revocation account_id passed the database constraint"),
            device_id: row.device_id,
            session_id: row.session_id,
            scope: row.scope,
            reason_code: row.reason_code,
            revoked_at: row.revoked_at,
            expires_at: row.expires_at,
        }
    }
}

#[cfg(test)]
mod account_summary_query_tests {
    use diesel_async::SimpleAsyncConnection;

    use super::*;

    /// The bootstrap answer is one authority snapshot plus the independent
    /// stream tails after it: nothing is paged by the authority
    /// (`realm_join_bootstrap`). What the Station still owes a restarting
    /// joiner is that the download it persisted is the one it recovers, that
    /// the snapshot the progress was measured against cannot be swapped under
    /// it, and that progress never regresses. Immutable wire cursors are a
    /// separate table and stay frozen throughout.
    #[tokio::test]
    async fn bootstrap_download_resumes_durably_without_mutating_wire_cursors() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgSyncCursorStore { pool: pool.clone() };
        let realm_id: arkret_wire::RealmId =
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
                .parse()
                .unwrap();
        let station_id: arkret_identifiers::DidCoreId =
            "ak:did_core:web:origin.example".parse().unwrap();
        let applicant: arkret_identifiers::DidCoreId =
            "ak:did_core:web:applicant.example".parse().unwrap();
        let observed_at =
            chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();

        let stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let commit_id = |seed: u8| arkret_wire::RealmCommitId::from_digest([seed; 32]);
        let signature = |context| arkret_wire::DetachedObjectSignature {
            context,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_wire::DidUrl::new("did:web:origin.example#authority")
                .unwrap(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "aa".repeat(32))).unwrap(),
            created_at: observed_at,
            sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
        };
        let snapshot = arkret_wire::RealmStateSnapshot {
            snapshot_id: arkret_wire::RealmSnapshotId::from_digest([7; 32]),
            realm_id: realm_id.clone(),
            governance_generation: 1,
            visible_stream_heads: vec![arkret_wire::CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: 0,
                commit_id: commit_id(1),
            }],
            current_state_entries: vec![],
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::SinceJoin,
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref: stream_ref.clone(),
                    oldest_position: 0,
                }],
            },
            created_at: observed_at,
            signature: signature(arkret_wire::DetachedSignatureContext::RealmSnapshot),
        };
        let stream_row = |position: u64, previous: Option<arkret_wire::RealmCommitId>| {
            let event = arkret_wire::test_support::raw_event(
                arkret_wire::EventKind::MemberState.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                applicant.clone(),
                station_id.clone(),
                serde_json::json!({
                    "member_id": arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                        applicant.clone(),
                        station_id.clone(),
                    )),
                    "membership": "join",
                    "stream_position": position
                }),
            )
            .unwrap();
            arkret_wire::CommittedEventFullView {
                commit: arkret_wire::RealmCommit {
                    producer_signer_fact_digest: None,
                    commit_id: commit_id(u8::try_from(position).unwrap() + 2),
                    realm_id: realm_id.clone(),
                    stream_ref: stream_ref.clone(),
                    stream_position: position,
                    previous_commit_ref: previous,
                    event_ref: event.event_id.clone(),
                    governance_generation: 1,
                    authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                        event.event_id.clone(),
                    ),
                    committed_at: observed_at,
                    signature: signature(arkret_wire::DetachedSignatureContext::RealmCommit),
                },
                event,
            }
        };
        let first_row = stream_row(1, Some(commit_id(1)));
        let second_row = stream_row(2, Some(first_row.commit.commit_id.clone()));

        let partial = RealmJoinDownload {
            snapshot: snapshot.clone(),
            stream_heads: vec![arkret_wire::CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: 2,
                commit_id: second_row.commit.commit_id.clone(),
            }],
            items: vec![first_row.clone()],
            next_cursor: Some("scan".into()),
            expires_at: observed_at + chrono::Duration::seconds(300),
        };
        store
            .save_realm_join_download("download-test", &partial)
            .await
            .unwrap();

        let mut complete = partial.clone();
        complete.items.push(second_row);
        complete.next_cursor = None;
        store
            .save_realm_join_download("download-test", &complete)
            .await
            .unwrap();
        // Re-saving the identical terminal state is an idempotent no-op.
        store
            .save_realm_join_download("download-test", &complete)
            .await
            .unwrap();

        // A fresh adapter must recover the terminal scan, not the initial one.
        let restarted = PgSyncCursorStore { pool };
        let restored = restarted
            .realm_join_download("download-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.items.len(), 2);
        assert!(restored.next_cursor.is_none());

        // Progress may not regress back to the shorter scan.
        assert!(
            restarted
                .save_realm_join_download("download-test", &partial)
                .await
                .is_err()
        );
        // Nor may the snapshot the scan was measured against be swapped.
        let mut changed_context = complete.clone();
        changed_context.snapshot.governance_generation = 2;
        assert!(
            restarted
                .save_realm_join_download("download-test", &changed_context)
                .await
                .is_err()
        );

        let mut cursor = SyncCursorRecord {
            handle: "immutable-cursor-test".into(),
            binding_subject: None,
            device_id: None,
            session_id: None,
            service_id: station_id,
            filter_digest: None,
            purpose: "stream".into(),
            positions: Some(serde_json::json!({"page": 0})),
            target: None,
            issued_at_ms: observed_at.timestamp_millis(),
            expires_at_ms: complete.expires_at.timestamp_millis(),
        };
        restarted.upsert(&cursor).await.unwrap();
        cursor.positions = Some(serde_json::json!({"page": 1}));
        assert!(restarted.upsert(&cursor).await.is_err());
        assert_eq!(
            restarted
                .get(&cursor.handle)
                .await
                .unwrap()
                .unwrap()
                .positions,
            Some(serde_json::json!({"page": 0}))
        );
    }

    #[tokio::test]
    async fn frozen_pages_keep_scan_keys_and_recheck_current_permission() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pg_conn(&pool).await.unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:exact.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ))
        .canonical_key()
        .unwrap();
        let other = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            "ak:did_core:web:other.example".parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        ))
        .canonical_key()
        .unwrap();
        let fixture = "INSERT INTO account_summary_current
            (actor_key, realm_id, revision, membership, title, available) VALUES
            ('exact-account', 'a', 4, 'knock', NULL, TRUE),
            ('exact-account', 'b', 5, NULL, NULL, TRUE),
            ('other-account', 'secret', 6, 'join', 'secret', TRUE);
            INSERT INTO account_summary_versions
            (actor_key, realm_id, revision, activity_position, valid_until, membership, title, invalidated) VALUES
            ('exact-account', 'a', 1, 1, 4, 'join', 'old private title', FALSE),
            ('exact-account', 'b', 2, 2, 5, 'join', 'revoked title', FALSE),
            ('exact-account', 'a', 4, 4, NULL, 'knock', NULL, TRUE),
            ('exact-account', 'b', 5, 5, NULL, NULL, NULL, TRUE),
            ('other-account', 'secret', 6, 6, NULL, 'join', 'secret', FALSE);"
            .replace("exact-account", &actor).replace("other-account", &other);
        conn.batch_execute(&fixture).await.unwrap();
        drop(conn);
        let store = PgSyncCursorStore { pool };
        let first = store
            .account_summary_page(&actor, 2, None, 2)
            .await
            .unwrap();
        assert_eq!(
            first.iter().map(|row| row.key.revision).collect::<Vec<_>>(),
            vec![5, 4]
        );
        let second = store
            .account_summary_page(&actor, 2, Some(&first[1].key), 2)
            .await
            .unwrap();
        assert_eq!(
            second
                .iter()
                .map(|row| row.key.revision)
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
        assert!(second[0].current_membership.is_none());
        assert_eq!(second[1].current_membership.as_deref(), Some("knock"));
        assert_eq!(second[1].membership.as_deref(), Some("join"));
        let tail = store
            .account_summary_page(&actor, 2, Some(&second[1].key), 2)
            .await
            .unwrap();
        assert!(tail.is_empty());
        let changes = store.account_summary_changes(&actor, 2, 1).await.unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].key.revision, 4);
        assert_eq!(
            store.account_summary_changes(&actor, 4, 1).await.unwrap()[0]
                .key
                .revision,
            5
        );
    }
}
