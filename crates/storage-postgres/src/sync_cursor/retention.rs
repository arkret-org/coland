//! Durable read retention, shared by snapshot creation, cursor writes and GC.
use super::*;
use crate::{AsyncPgConnection, PgTransactionError};

pub(crate) const LOCK_KEY: i64 = 0x414b_5359_4e43;

#[derive(QueryableByName)]
struct Floors {
    #[diesel(sql_type = BigInt)]
    summary_floor: i64,
    #[diesel(sql_type = BigInt)]
    global_floor: i64,
}

pub(crate) async fn lock(
    conn: &mut AsyncPgConnection,
    exclusive: bool,
) -> Result<(), PgTransactionError> {
    let sql = if exclusive {
        "SELECT pg_advisory_xact_lock($1)"
    } else {
        "SELECT pg_advisory_xact_lock_shared($1)"
    };
    sql_query(sql)
        .bind::<BigInt, _>(LOCK_KEY)
        .execute(conn)
        .await?;
    Ok(())
}

/// The caller keeps the transaction open through its indexed read/write.
pub(super) async fn check(
    conn: &mut AsyncPgConnection,
    summary: Option<i64>,
    global: Option<i64>,
) -> Result<(), PgTransactionError> {
    lock(conn, false).await?;
    let floors =
        sql_query("SELECT summary_floor,global_floor FROM account_sync_retention WHERE singleton")
            .get_result::<Floors>(conn)
            .await?;
    if summary.is_some_and(|cut| cut < floors.summary_floor)
        || global.is_some_and(|cut| cut < floors.global_floor)
    {
        return Err(PersistenceError::Conflict(
            "cursor_expired: account read position was reclaimed".into(),
        )
        .into());
    }
    Ok(())
}

pub(super) async fn freeze(pool: &PgPool) -> PersistenceResult<(i64, i64)> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| freeze_on_connection(conn).await)
        .await
        .map_err(PgTransactionError::into_persistence)
}

/// Call before reading window authority or coverage, in the same transaction.
/// The caller must not hold a clock/source row lock before taking this lease.
pub(super) async fn freeze_on_connection(
    conn: &mut AsyncPgConnection,
) -> Result<(i64, i64), PgTransactionError> {
    // Acquire before taking the statement snapshot: waiting on GC with an
    // earlier MVCC snapshot could otherwise register an already-reclaimed cut.
    lock(conn, true).await?;
    let cut = sql_query("SELECT s.revision AS summary_revision,g.revision AS global_revision FROM account_summary_clock s CROSS JOIN account_global_clock g WHERE s.singleton AND g.singleton FOR SHARE OF s")
            .get_result::<AccountWatermarksRow>(&mut *conn).await?;
    // One global protection bucket per minute coalesces concurrent initial
    // reads. It grants no access authority and contains no account data.
    sql_query("INSERT INTO account_sync_snapshot_reservations(bucket,summary_floor,global_floor,expires_at_ms) VALUES(floor(extract(epoch FROM clock_timestamp())/60)::bigint,$1,$2,(extract(epoch FROM clock_timestamp())*1000)::bigint+3660000) ON CONFLICT(bucket) DO UPDATE SET summary_floor=LEAST(account_sync_snapshot_reservations.summary_floor,EXCLUDED.summary_floor),global_floor=LEAST(account_sync_snapshot_reservations.global_floor,EXCLUDED.global_floor),expires_at_ms=GREATEST(account_sync_snapshot_reservations.expires_at_ms,EXCLUDED.expires_at_ms)")
            .bind::<BigInt,_>(cut.summary_revision).bind::<BigInt,_>(cut.global_revision).execute(&mut *conn).await?;
    Ok((cut.summary_revision, cut.global_revision))
}

fn integer(value: Option<&Value>) -> PersistenceResult<i64> {
    value
        .and_then(Value::as_i64)
        .filter(|value| *value >= 0)
        .ok_or_else(|| {
            PersistenceError::SchemaViolation(
                "account retention position is absent or negative".into(),
            )
        })
}

pub(super) fn cursor_floors(record: &SyncCursorRecord) -> PersistenceResult<Option<(i64, i64)>> {
    match record.purpose.as_str() {
        "realm_list" => {
            let target = record
                .target
                .as_ref()
                .ok_or_else(|| PersistenceError::SchemaViolation("list target absent".into()))?;
            Ok(Some((
                integer(target.get("watermark"))?,
                integer(target.get("global_watermark"))?,
            )))
        }
        "ak.self.account.stream.subscribe.v1" => {
            let positions = record.positions.as_ref().ok_or_else(|| {
                PersistenceError::SchemaViolation("account positions absent".into())
            })?;
            let summary_position = integer(positions.get("account_summary"))?;
            let progress = positions
                .get("global_baseline")
                .filter(|value| !value.is_null());
            // Before the first account baseline, zero is an uninitialized
            // summary position. Only delivered detail windows retain history.
            let mut summary = progress.map_or(i64::MAX, |_| summary_position);
            if let Some(details) = positions.get("detail_positions") {
                let details = details.as_object().ok_or_else(|| {
                    PersistenceError::SchemaViolation(
                        "current detail positions are not an object".into(),
                    )
                })?;
                for detail in details.values() {
                    summary = summary.min(integer(detail.get("retained_revision"))?);
                }
            }
            let Some(progress) = progress else {
                // A Realm detail turn may precede the first account-global
                // baseline. It has no global history to retain; pinning
                // revision zero rejects valid cursors after global GC moves.
                return Ok(Some((summary, i64::MAX)));
            };
            let snapshot = integer(progress.get("snapshot_watermark"))?;
            let completed = progress
                .get("completed")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    PersistenceError::SchemaViolation("global completed channels absent".into())
                })?;
            let mut global = i64::MAX;
            for channel in [
                "account_data_events",
                "station_cas",
                "notifications",
                "device_lists",
            ] {
                let position = if completed
                    .iter()
                    .any(|value| value.as_str() == Some(channel))
                {
                    integer(
                        progress
                            .get("positions")
                            .and_then(|positions| positions.get(channel)),
                    )?
                } else {
                    snapshot
                };
                global = global.min(position);
            }
            Ok(Some((summary, global)))
        }
        _ => Ok(None),
    }
}

pub(super) async fn save_cursor(
    conn: &mut AsyncPgConnection,
    record: &SyncCursorRecord,
    floors: Option<(i64, i64)>,
) -> Result<(), PgTransactionError> {
    if let Some((summary, global)) = floors {
        sql_query("INSERT INTO account_sync_cursor_retention(handle,summary_floor,global_floor) VALUES($1,$2,$3) ON CONFLICT(handle) DO NOTHING")
            .bind::<Text,_>(&record.handle).bind::<BigInt,_>(summary).bind::<BigInt,_>(global).execute(conn).await?;
    }
    Ok(())
}

/// Rows each reclaimable class loses per batch; each batch is one short
/// transaction on the exclusive retention lock.
const PRUNE_BATCH_ROWS: usize = 10_000;

/// Upper bound on batches per sweep, so one sweep never holds the retention
/// lock indefinitely; any remainder is the next sweep's first batch.
const MAX_PRUNE_BATCHES_PER_SWEEP: usize = 1_000;

/// Drain every reclaimable class (0441): batches repeat while any class
/// filled its batch, so the backlog after a sweep is empty rather than
/// growing whenever expiries outpace one batch per sweep interval.
pub(super) async fn prune(pool: &PgPool, now_ms: i64) -> PersistenceResult<usize> {
    let mut pruned = 0;
    for _ in 0..MAX_PRUNE_BATCHES_PER_SWEEP {
        let (handles, saturated) = prune_batch(pool, now_ms).await?;
        pruned += handles;
        if !saturated {
            return Ok(pruned);
        }
    }
    tracing::warn!(
        pruned,
        "sync retention sweep stopped at its batch bound; the remainder waits for the next sweep"
    );
    Ok(pruned)
}

/// One bounded batch per class. Returns the expired handles removed and
/// whether any class filled its batch.
async fn prune_batch(pool: &PgPool, now_ms: i64) -> PersistenceResult<(usize, bool)> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_,PgTransactionError,_>(async |conn| {
        lock(conn,true).await?;
        let batch = PRUNE_BATCH_ROWS as i64;
        let mut saturated = false;
        let pruned = sql_query("DELETE FROM sync_cursor_handles WHERE id IN (SELECT id FROM sync_cursor_handles WHERE expires_at_ms<=$1 ORDER BY expires_at_ms LIMIT $2)")
            .bind::<BigInt,_>(now_ms).bind::<BigInt,_>(batch).execute(&mut *conn).await?;
        saturated |= pruned == PRUNE_BATCH_ROWS;
        saturated |= sql_query("DELETE FROM account_sync_snapshot_reservations WHERE bucket IN (SELECT bucket FROM account_sync_snapshot_reservations WHERE expires_at_ms<=$1 ORDER BY bucket LIMIT $2)")
            .bind::<BigInt,_>(now_ms).bind::<BigInt,_>(batch).execute(&mut *conn).await? == PRUNE_BATCH_ROWS;
        // Indexed minima avoid scanning every active handle. Expired handles
        // awaiting the next bounded deletion batch conservatively retain data.
        let floors = sql_query("SELECT LEAST(COALESCE((SELECT min(summary_floor) FROM account_sync_snapshot_reservations),s.revision),COALESCE((SELECT summary_floor FROM account_sync_cursor_retention ORDER BY summary_floor LIMIT 1),s.revision)) AS summary_floor,LEAST(COALESCE((SELECT min(global_floor) FROM account_sync_snapshot_reservations),g.revision),COALESCE((SELECT global_floor FROM account_sync_cursor_retention ORDER BY global_floor LIMIT 1),g.revision)) AS global_floor FROM account_summary_clock s CROSS JOIN account_global_clock g WHERE s.singleton AND g.singleton")
            .get_result::<Floors>(&mut *conn).await?;
        sql_query("UPDATE account_sync_retention SET summary_floor=GREATEST(summary_floor,$1),global_floor=GREATEST(global_floor,$2) WHERE singleton")
            .bind::<BigInt,_>(floors.summary_floor).bind::<BigInt,_>(floors.global_floor).execute(&mut *conn).await?;
        // Closed versions only. Current values and tombstones remain available
        // to a fresh baseline.
        saturated |= sql_query("DELETE FROM account_summary_versions WHERE ctid IN (SELECT ctid FROM account_summary_versions WHERE valid_until<=$1 ORDER BY valid_until LIMIT $2)")
            .bind::<BigInt,_>(floors.summary_floor).bind::<BigInt,_>(batch).execute(&mut *conn).await? == PRUNE_BATCH_ROWS;
        saturated |= sql_query("DELETE FROM current_result_versions WHERE ctid IN (SELECT ctid FROM current_result_versions WHERE valid_until<=$1 ORDER BY valid_until LIMIT $2)")
            .bind::<BigInt,_>(floors.summary_floor).bind::<BigInt,_>(batch).execute(&mut *conn).await? == PRUNE_BATCH_ROWS;
        saturated |= sql_query("DELETE FROM account_global_versions WHERE ctid IN (SELECT ctid FROM account_global_versions WHERE valid_until<=$1 ORDER BY valid_until LIMIT $2)")
            .bind::<BigInt,_>(floors.global_floor).bind::<BigInt,_>(batch).execute(&mut *conn).await? == PRUNE_BATCH_ROWS;
        // Issued Realm snapshots share this lock: a window reservation is
        // registered under the shared side, so a reserved basis is never
        // reclaimed while its window is consumable.
        saturated |= crate::issued_realm_snapshots::prune_in_connection(conn, now_ms, batch).await?;
        Ok((pruned, saturated))
    }).await.map_err(PgTransactionError::into_persistence)
}

#[cfg(test)]
mod tests {
    use diesel_async::SimpleAsyncConnection;

    use super::*;

    #[tokio::test]
    async fn snapshot_then_cursor_retains_versions_and_expiry_rejects_old_positions() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgSyncCursorStore { pool: pool.clone() };
        let mut conn = pg_conn(&pool).await.unwrap();
        conn.batch_execute("UPDATE account_summary_clock SET revision=1; UPDATE account_global_clock SET revision=1;
            INSERT INTO account_summary_versions(actor_key,realm_id,revision,activity_position,membership,title,invalidated) VALUES('actor','realm',1,1,'join','old',false);
            INSERT INTO account_global_versions(actor_key,channel,item_key,channel_position,revision,payload) VALUES('actor','station_cas','key',1,1,'{}');
            INSERT INTO current_result_versions(realm_id,selector_key,revision,target_kind,target_key,payload) VALUES('realm','selector',1,'realm','','{}');").await.unwrap();
        assert_eq!(store.account_sync_watermarks().await.unwrap(), (1, 1));
        conn.batch_execute("UPDATE account_summary_clock SET revision=2; UPDATE account_global_clock SET revision=2;
            UPDATE account_summary_versions SET valid_until=2;
            INSERT INTO account_summary_versions(actor_key,realm_id,revision,activity_position,membership,title,invalidated) VALUES('actor','realm',2,2,'join','new',false);
            UPDATE account_global_versions SET valid_until=2;
            INSERT INTO account_global_versions(actor_key,channel,item_key,channel_position,revision,payload) VALUES('actor','station_cas','key',2,2,'{}');
            UPDATE current_result_versions SET valid_until=2;
            INSERT INTO current_result_versions(realm_id,selector_key,revision,target_kind,target_key,payload) VALUES('realm','selector',2,'realm','','{}');").await.unwrap();
        let now = Utc::now().timestamp_millis();
        store.prune_expired(now).await.unwrap();
        let frozen = store
            .account_global_page("actor", "station_cas", 1, "", None, 10)
            .await
            .unwrap();
        assert_eq!(frozen.len(), 1);
        assert_eq!(frozen[0].revision, 1);
        let retained_current =
            sql_query("SELECT count(*)::bigint AS revision FROM current_result_versions")
                .get_result::<SummaryWatermarkRow>(&mut *conn)
                .await
                .unwrap();
        assert_eq!(retained_current.revision, 2);
        let cursor = SyncCursorRecord {
            handle: "retained-list".into(),
            binding_subject: Some("account".into()),
            device_id: Some("device".into()),
            session_id: None,
            service_id: arkret_identifiers::DidCoreId::new("ak:did_core:web:station.example")
                .unwrap(),
            filter_digest: None,
            purpose: "realm_list".into(),
            positions: None,
            target: Some(serde_json::json!({"watermark":1,"global_watermark":1})),
            issued_at_ms: now,
            expires_at_ms: now + 3_600_000,
        };
        store.upsert(&cursor).await.unwrap();
        conn.batch_execute("UPDATE account_sync_snapshot_reservations SET expires_at_ms=0")
            .await
            .unwrap();
        store.prune_expired(now).await.unwrap();
        let restarted = PgSyncCursorStore { pool: pool.clone() };
        assert_eq!(
            restarted
                .account_global_page("actor", "station_cas", 1, "", None, 10)
                .await
                .unwrap()[0]
                .revision,
            1
        );
        store.delete(&cursor.handle).await.unwrap();
        store.prune_expired(now).await.unwrap();
        assert!(
            store
                .account_global_page("actor", "station_cas", 1, "", None, 10)
                .await
                .is_err()
        );
        assert!(
            store
                .account_summary_page("actor", 1, None, 10)
                .await
                .is_err()
        );
        assert!(store.account_summary_changes("actor", 1, 10).await.is_err());
        assert!(store.upsert(&cursor).await.is_err());
        assert_eq!(
            store
                .account_global_page("actor", "station_cas", 2, "", None, 10)
                .await
                .unwrap()
                .len(),
            1
        );
        let count = sql_query("SELECT count(*)::bigint AS revision FROM account_global_versions")
            .get_result::<SummaryWatermarkRow>(&mut *conn)
            .await
            .unwrap();
        assert_eq!(count.revision, 1);
        let count = sql_query("SELECT count(*)::bigint AS revision FROM current_result_versions")
            .get_result::<SummaryWatermarkRow>(&mut *conn)
            .await
            .unwrap();
        assert_eq!(count.revision, 1);
    }

    /// A first Realm-detail turn has not chosen either account baseline cut.
    /// Real PostgreSQL must accept it after both retention floors advance.
    #[tokio::test]
    async fn detail_cursor_without_global_baseline_does_not_pin_revision_zero() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pg_conn(&pool).await.unwrap();
        conn.batch_execute(
            "UPDATE account_summary_clock SET revision=5;
            UPDATE account_global_clock SET revision=5;
            UPDATE account_sync_retention SET summary_floor=5,global_floor=5",
        )
        .await
        .unwrap();
        let now = Utc::now().timestamp_millis();
        let cursor = SyncCursorRecord {
            handle: "detail-before-global".into(),
            binding_subject: Some("account".into()),
            device_id: Some("device".into()),
            session_id: None,
            service_id: arkret_identifiers::DidCoreId::new("ak:did_core:web:station.example")
                .unwrap(),
            filter_digest: Some("digest".into()),
            purpose: "ak.self.account.stream.subscribe.v1".into(),
            positions: Some(serde_json::json!({
                "account_summary": 0,
                "global_baseline": null,
                "detail_positions": {},
            })),
            target: None,
            issued_at_ms: now,
            expires_at_ms: now + 3_600_000,
        };
        assert_eq!(cursor_floors(&cursor).unwrap(), Some((i64::MAX, i64::MAX)));
        let store = PgSyncCursorStore { pool };
        store.upsert(&cursor).await.unwrap();
        let mut detail = cursor.clone();
        detail.handle = "detail-retains-its-window".into();
        detail.positions.as_mut().unwrap()["detail_positions"] =
            serde_json::json!({"realm": {"retained_revision": 5}});
        assert_eq!(cursor_floors(&detail).unwrap(), Some((5, i64::MAX)));
        store.upsert(&detail).await.unwrap();
        detail.handle = "detail-window-was-reclaimed".into();
        detail.positions.as_mut().unwrap()["detail_positions"]["realm"]["retained_revision"] =
            serde_json::json!(4);
        assert!(matches!(
            store.upsert(&detail).await,
            Err(PersistenceError::Conflict(_))
        ));
    }

    /// Real PostgreSQL: an Account stream cursor that carries a frozen
    /// Realm window keeps the window's `retained_revision` readable even after
    /// its own summary position moved on and the minute reservation expired;
    /// a detail progress without the floor is refused, never defaulted.
    #[tokio::test]
    async fn account_cursor_detail_progress_holds_its_retained_revision() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgSyncCursorStore { pool: pool.clone() };
        let mut conn = pg_conn(&pool).await.unwrap();
        conn.batch_execute("UPDATE account_summary_clock SET revision=1; UPDATE account_global_clock SET revision=1;
            INSERT INTO current_result_versions(realm_id,selector_key,revision,target_kind,target_key,payload) VALUES('realm','selector',1,'realm','','{}');").await.unwrap();
        let (retained_revision, _) = store.account_sync_watermarks().await.unwrap();
        assert_eq!(retained_revision, 1);
        conn.batch_execute("UPDATE account_summary_clock SET revision=2; UPDATE account_global_clock SET revision=2;
            UPDATE current_result_versions SET valid_until=2;
            INSERT INTO current_result_versions(realm_id,selector_key,revision,target_kind,target_key,payload) VALUES('realm','selector',2,'realm','','{}');").await.unwrap();
        let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x61; 32],
        ));
        let now = Utc::now().timestamp_millis();
        let progress = coland_storage::AccountDetailProgress {
            window_cursor: arkret_wire::Cursor::new("ak:cursor:window".to_owned()).unwrap(),
            expires_at_ms: now + 3_600_000,
            retained_revision,
            governance_generation: 0,
            stream_heads: vec![arkret_wire::CommitStreamHead {
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: realm_id.clone(),
                },
                stream_position: 8,
                commit_id: arkret_wire::RealmCommitId::from_digest([0x62; 32]),
            }],
            streams_limited: false,
        };
        let record = |handle: &str, detail: Value| SyncCursorRecord {
            handle: handle.into(),
            binding_subject: Some("account".into()),
            device_id: Some("device".into()),
            session_id: None,
            service_id: arkret_identifiers::DidCoreId::new("ak:did_core:web:station.example")
                .unwrap(),
            filter_digest: Some("digest".into()),
            purpose: "ak.self.account.stream.subscribe.v1".into(),
            positions: Some(serde_json::json!({
                "account_summary": 2,
                "global_baseline": null,
                "detail_positions": {(realm_id.as_str()): detail},
            })),
            target: None,
            issued_at_ms: now,
            expires_at_ms: now + 3_600_000,
        };
        let detail = serde_json::to_value(&progress).unwrap();
        let mut without_floor = detail.clone();
        without_floor
            .as_object_mut()
            .unwrap()
            .remove("retained_revision");
        assert!(matches!(
            store.upsert(&record("no-floor", without_floor)).await,
            Err(PersistenceError::SchemaViolation(_))
        ));
        let cursor = record("window-cursor", detail);
        assert_eq!(cursor_floors(&cursor).unwrap(), Some((1, i64::MAX)));
        store.upsert(&cursor).await.unwrap();

        // The minute reservation lapses; only the cursor now holds revision 1.
        conn.batch_execute("UPDATE account_sync_snapshot_reservations SET expires_at_ms=0")
            .await
            .unwrap();
        store.prune_expired(now).await.unwrap();
        let versions = || async {
            sql_query("SELECT count(*)::bigint AS revision FROM current_result_versions")
                .get_result::<SummaryWatermarkRow>(&mut *pg_conn(&pool).await.unwrap())
                .await
                .unwrap()
                .revision
        };
        assert_eq!(versions().await, 2);
        store.delete(&cursor.handle).await.unwrap();
        store.prune_expired(now).await.unwrap();
        assert_eq!(versions().await, 1);
    }

    /// One sweep drains a reclaimable backlog larger than a batch instead of
    /// leaving the remainder for later sweep intervals (0441).
    #[tokio::test]
    async fn one_sweep_drains_a_backlog_larger_than_one_batch() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgSyncCursorStore { pool: pool.clone() };
        let mut conn = pg_conn(&pool).await.unwrap();
        let backlog = 2 * PRUNE_BATCH_ROWS + 1;
        conn.batch_execute(&format!(
            "UPDATE account_summary_clock SET revision=10; UPDATE account_global_clock SET revision=10;
            INSERT INTO current_result_versions(realm_id,selector_key,revision,valid_until,target_kind,target_key,payload)
              SELECT 'realm','selector-'||n,1,2,'realm','','{{}}' FROM generate_series(1,{backlog}) n;"
        ))
        .await
        .unwrap();
        store
            .prune_expired(Utc::now().timestamp_millis())
            .await
            .unwrap();
        let remaining =
            sql_query("SELECT count(*)::bigint AS revision FROM current_result_versions")
                .get_result::<SummaryWatermarkRow>(&mut *conn)
                .await
                .unwrap();
        assert_eq!(remaining.revision, 0);
    }

    #[tokio::test]
    async fn waiting_snapshot_reads_its_cut_after_the_gc_lock() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pg_conn(&pool).await.unwrap();
        conn.batch_execute("BEGIN").await.unwrap();
        lock(&mut conn, true)
            .await
            .map_err(PgTransactionError::into_persistence)
            .unwrap();
        let freeze_pool = pool.clone();
        let mut pending = tokio::spawn(async move { freeze(&freeze_pool).await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut pending)
                .await
                .is_err()
        );
        conn.batch_execute("UPDATE account_summary_clock SET revision=7; UPDATE account_global_clock SET revision=9;
            UPDATE account_sync_retention SET summary_floor=7,global_floor=9; COMMIT").await.unwrap();
        assert_eq!(pending.await.unwrap().unwrap(), (7, 9));
        let reserved =
            sql_query("SELECT summary_floor,global_floor FROM account_sync_snapshot_reservations")
                .get_result::<Floors>(&mut *conn)
                .await
                .unwrap();
        assert_eq!((reserved.summary_floor, reserved.global_floor), (7, 9));
    }
}
