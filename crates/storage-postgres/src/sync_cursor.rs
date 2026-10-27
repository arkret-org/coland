use super::{
    BigInt, CursorRevocation, Jsonb, Nullable, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, QueryableByName, RunQueryDsl, SyncCursorRecord, SyncCursorStore,
    Text, Timestamptz, Utc, Value, async_trait, pg_conn, sql_query, sql_types,
};
pub(crate) mod retention;
use diesel_async::AsyncConnection;
pub struct PgSyncCursorStore {
    pub pool: PgPool,
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
    async fn account_sync_watermarks(&self) -> PersistenceResult<(i64, i64)> {
        retention::freeze(&self.pool).await
    }
    async fn account_global_watermark(&self) -> PersistenceResult<i64> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("SELECT revision FROM account_global_clock WHERE singleton")
            .get_result::<SummaryWatermarkRow>(&mut conn)
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
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT COALESCE(MAX(channel_position), 0)::bigint AS revision \
             FROM account_global_versions \
             WHERE actor_key = $1 AND channel = $2 AND revision <= $3",
        )
        .bind::<Text, _>(actor_key)
        .bind::<Text, _>(channel)
        .bind::<BigInt, _>(watermark)
        .get_result::<SummaryWatermarkRow>(&mut conn)
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
        let mut conn = crate::pg_db(&self.pool);
        sql_query("SELECT revision FROM account_summary_clock WHERE singleton")
            .get_result::<SummaryWatermarkRow>(&mut conn)
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
        get_in_connection(&mut conn, handle).await
    }

    async fn upsert(&self, record: &SyncCursorRecord) -> PersistenceResult<()> {
        self.upsert_with_inputs(record, &[]).await
    }

    async fn upsert_with_inputs(
        &self,
        record: &SyncCursorRecord,
        inputs: &[SyncCursorRecord],
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, crate::PgTransactionError, _>(async |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                .execute(&mut *conn)
                .await?;
            upsert_in_connection(conn, record, inputs).await
        })
        .await
        .map_err(crate::PgTransactionError::into_persistence)
    }

    async fn delete(&self, handle: &str) -> PersistenceResult<bool> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM sync_cursor_handles WHERE id = $1")
            .bind::<Text, _>(handle)
            .execute(&mut conn)
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
        conn.transaction::<_,crate::PgTransactionError,_>(async |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED").execute(&mut *conn).await?;
            let subject=String::from_utf8(arkret_canonical::canonical_json_bytes(&record.account_id).map_err(PersistenceError::database)?).map_err(PersistenceError::database)?;
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))").bind::<Text,_>(format!("cursor-authority:{subject}")).execute(&mut *conn).await?;
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
        .await?;
        Ok(())
        }).await.map_err(crate::PgTransactionError::into_persistence)
    }

    async fn active_revocations(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> PersistenceResult<Vec<CursorRevocation>> {
        let mut conn = crate::pg_db(&self.pool);
        let rows = sql_query(
            "SELECT cursor_digest, account_id, device_id, session_id, scope, reason_code, revoked_at, expires_at \
             FROM sync_cursor_revocations WHERE expires_at > $1 \
             ORDER BY revoked_at ASC",
        )
        .bind::<Timestamptz, _>(now)
        .load::<CursorRevocationRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(rows.into_iter().map(CursorRevocation::from).collect())
    }
}
pub(crate) async fn validate_issuance_inputs(
    conn: &mut super::AsyncPgConnection,
    inputs: &[SyncCursorRecord],
) -> Result<(), crate::PgTransactionError> {
    let subjects = inputs
        .iter()
        .filter_map(|input| input.binding_subject.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    for subject in subjects {
        sql_query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))")
            .bind::<Text, _>(format!("cursor-authority:{subject}"))
            .execute(&mut *conn)
            .await?;
    }
    let now = Utc::now();
    for input in inputs {
        if now.timestamp_millis() >= input.expires_at_ms {
            return Err(PersistenceError::Conflict(
                "cursor_expired: input authority expired during issuance".to_owned(),
            )
            .into());
        }
        let current: SyncCursorRecord=sql_query("SELECT id AS handle,binding_subject,device_id,session_id,service_id,filter_digest,purpose,positions,target,issued_at_ms,expires_at_ms FROM sync_cursor_handles WHERE id=$1")
            .bind::<Text,_>(&input.handle).get_result::<SyncCursorRow>(&mut *conn).await.optional()?.map(SyncCursorRecord::from)
            .ok_or_else(||PersistenceError::Conflict("cursor_integrity_invalid: input issuance is absent".to_owned()))?;
        if input != &current {
            return Err(PersistenceError::Conflict(
                "cursor_integrity_invalid: input issuance changed".to_owned(),
            )
            .into());
        }
        let Some(subject) = input.binding_subject.as_deref() else {
            continue;
        };
        let Ok(account) = serde_json::from_str::<arkret_wire::AccountId>(subject) else {
            continue;
        };
        let entries=sql_query("SELECT cursor_digest,account_id,device_id,session_id,scope,reason_code,revoked_at,expires_at FROM sync_cursor_revocations WHERE account_id=$1 AND expires_at>$2")
            .bind::<Jsonb,_>(serde_json::to_value(&account).map_err(PersistenceError::database)?).bind::<Timestamptz,_>(now).load::<CursorRevocationRow>(&mut *conn).await?;
        let digest = arkret_canonical::sha256_hex(input.handle.as_bytes());
        let revoked = entries.iter().any(|entry| match entry.scope.as_str() {
            "this_cursor" => entry.cursor_digest == digest,
            "same_device" => entry.device_id == input.device_id,
            "same_session" => {
                entry.device_id == input.device_id
                    && input.session_id.is_some()
                    && entry.session_id == input.session_id
            }
            _ => false,
        });
        if revoked {
            return Err(PersistenceError::Conflict(
                "cursor_revoked: input authority revoked during issuance".to_owned(),
            )
            .into());
        }
    }
    Ok(())
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

    /// An immutable cursor cannot be rewritten through another store instance.
    #[tokio::test]
    async fn cursor_issuance_remains_immutable_across_store_restart() {
        let database = crate::test_database::TestDatabase::lease().await;
        let store = PgSyncCursorStore {
            pool: database.pool(),
        };
        let station_id = "ak:did_core:web:origin.example".parse().unwrap();
        let observed_at = Utc::now();
        let restarted = PgSyncCursorStore {
            pool: database.pool(),
        };
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
            expires_at_ms: (observed_at + chrono::Duration::seconds(300)).timestamp_millis(),
        };
        store.upsert(&cursor).await.unwrap();
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

pub(crate) async fn upsert_in_connection(
    conn: &mut super::AsyncPgConnection,
    record: &SyncCursorRecord,
    inputs: &[SyncCursorRecord],
) -> Result<(), crate::PgTransactionError> {
    let floors = retention::cursor_floors(record)?;
    if let Some((summary, global)) = floors {
        retention::check(conn, Some(summary), Some(global)).await?;
    }
    if let Some(subject) = record.binding_subject.as_deref() {
        if let Ok(owner) = serde_json::from_str::<arkret_wire::AccountId>(subject) {
            crate::account_private_erasure::require_private_write_in_connection(conn, &owner)
                .await?;
        }
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
    validate_issuance_inputs(conn, inputs).await?;
    retention::save_cursor(conn, record, floors).await?;
    Ok(())
}

pub(crate) async fn get_in_connection(
    conn: &mut super::AsyncPgConnection,
    handle: &str,
) -> PersistenceResult<Option<SyncCursorRecord>> {
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
