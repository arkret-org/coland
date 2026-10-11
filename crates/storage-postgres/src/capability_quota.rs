//! The logical quota authority of hard grant quotas
//! (`authz/constraint-schema.md` §8.1).
//!
//! A [`QuotaReservation`] names one `(grant, constraint, counter key,
//! window)` counter. [`try_reserve_in_connection`] performs every reservation
//! a satisfied grant owes inside the caller's accepting transaction, so the
//! counter and the operation it admits commit or roll back together: a
//! refused operation consumes nothing, and two concurrent operations cannot
//! both observe the last remaining unit. One consumption row per operation
//! identity counts an exact retry once.

use coland_storage::QuotaReservation;

use super::{
    AsyncPgConnection, BigInt, OptionalExtension, PersistenceError, PersistenceResult,
    QueryableByName, RunQueryDsl, Text, sql_query,
};

#[derive(QueryableByName)]
struct ConsumedRow {
    #[diesel(sql_type = BigInt)]
    consumed: i64,
}

#[derive(QueryableByName)]
struct BucketRow {
    #[diesel(sql_type = BigInt)]
    level: i64,
    #[diesel(sql_type = BigInt)]
    refilled_at_ms: i64,
}

fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Reserve every one of `reservations` for `operation_identity`, or none of
/// them. `Ok(false)` means a quota is exhausted and nothing was written.
pub(crate) async fn try_reserve_in_connection(
    conn: &mut AsyncPgConnection,
    reservations: &[QuotaReservation],
    operation_identity: &str,
) -> PersistenceResult<bool> {
    if reservations.is_empty() {
        return Ok(true);
    }
    sql_query("SAVEPOINT capability_quota_reservation")
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let mut ordered = reservations.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        (&left.grant_id, &left.constraint_key, &left.counter_key).cmp(&(
            &right.grant_id,
            &right.constraint_key,
            &right.counter_key,
        ))
    });
    let mut reserved = true;
    for reservation in ordered {
        if !reserve_one(conn, reservation, operation_identity).await? {
            reserved = false;
            break;
        }
    }
    let statement = if reserved {
        "RELEASE SAVEPOINT capability_quota_reservation"
    } else {
        "ROLLBACK TO SAVEPOINT capability_quota_reservation"
    };
    sql_query(statement)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(reserved)
}

async fn reserve_one(
    conn: &mut AsyncPgConnection,
    reservation: &QuotaReservation,
    operation_identity: &str,
) -> PersistenceResult<bool> {
    let first_use = sql_query(
        "INSERT INTO capability_quota_consumptions \
         (grant_id,constraint_key,operation_identity,counter_key,window_id) \
         VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(reservation.grant_id.as_str())
    .bind::<Text, _>(&reservation.constraint_key)
    .bind::<Text, _>(operation_identity)
    .bind::<Text, _>(&reservation.counter_key)
    .bind::<BigInt, _>(reservation.window_id)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if first_use == 0 {
        // The same operation identity already holds this reservation.
        return Ok(true);
    }
    if reservation.max_operations == 0 {
        return Ok(false);
    }
    let counted = sql_query(
        "INSERT INTO capability_quota_counters \
         (grant_id,constraint_key,counter_key,window_id,consumed) VALUES($1,$2,$3,$4,1) \
         ON CONFLICT (grant_id,constraint_key,counter_key,window_id) DO UPDATE \
         SET consumed=capability_quota_counters.consumed+1 \
         WHERE capability_quota_counters.consumed < $5 RETURNING consumed",
    )
    .bind::<Text, _>(reservation.grant_id.as_str())
    .bind::<Text, _>(&reservation.constraint_key)
    .bind::<Text, _>(&reservation.counter_key)
    .bind::<BigInt, _>(reservation.window_id)
    .bind::<BigInt, _>(saturating_i64(reservation.max_operations))
    .get_result::<ConsumedRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if counted.is_none_or(|row| row.consumed > saturating_i64(reservation.max_operations)) {
        return Ok(false);
    }
    match reservation.burst {
        Some(burst) => take_bucket_token(conn, reservation, burst).await,
        None => Ok(true),
    }
}

/// §8.1 item 4: a token bucket of capacity `min(burst, max_operations)`
/// refilling at `max_operations / period` on the same authority. Levels are
/// kept in units of `1 / period_ms` token.
async fn take_bucket_token(
    conn: &mut AsyncPgConnection,
    reservation: &QuotaReservation,
    burst: u64,
) -> PersistenceResult<bool> {
    let period = i128::from(reservation.period_ms);
    let rate = i128::from(reservation.max_operations);
    let capacity = i128::from(burst.min(reservation.max_operations)) * period;
    let now = reservation.verification_ms;
    let capacity_level = i64::try_from(capacity).unwrap_or(i64::MAX);
    // The first reservation opens a full bucket; racing openers converge on
    // one row before either reads it under its row lock.
    sql_query(
        "INSERT INTO capability_quota_buckets \
         (grant_id,constraint_key,counter_key,level,refilled_at_ms) VALUES($1,$2,$3,$4,$5) \
         ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(reservation.grant_id.as_str())
    .bind::<Text, _>(&reservation.constraint_key)
    .bind::<Text, _>(&reservation.counter_key)
    .bind::<BigInt, _>(capacity_level)
    .bind::<BigInt, _>(now)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let stored = sql_query(
        "SELECT level,refilled_at_ms FROM capability_quota_buckets \
         WHERE grant_id=$1 AND constraint_key=$2 AND counter_key=$3 FOR UPDATE",
    )
    .bind::<Text, _>(reservation.grant_id.as_str())
    .bind::<Text, _>(&reservation.constraint_key)
    .bind::<Text, _>(&reservation.counter_key)
    .get_result::<BucketRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let elapsed = i128::from(now.saturating_sub(stored.refilled_at_ms).max(0));
    let level = (i128::from(stored.level) + elapsed * rate).min(capacity);
    if level < period {
        return Ok(false);
    }
    let remaining = i64::try_from(level - period).unwrap_or(i64::MAX);
    sql_query(
        "UPDATE capability_quota_buckets SET level=$4,refilled_at_ms=$5 \
         WHERE grant_id=$1 AND constraint_key=$2 AND counter_key=$3",
    )
    .bind::<Text, _>(reservation.grant_id.as_str())
    .bind::<Text, _>(&reservation.constraint_key)
    .bind::<Text, _>(&reservation.counter_key)
    .bind::<BigInt, _>(remaining)
    .bind::<BigInt, _>(stored.refilled_at_ms.max(now))
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_database::TestDatabase;

    fn reservation(seed: u8, counter: &str, max_operations: u64) -> QuotaReservation {
        QuotaReservation {
            grant_id: arkret_wire::GrantId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [seed; 32],
            )),
            constraint_key: "id:rate".into(),
            counter_key: counter.into(),
            window_id: 1,
            max_operations,
            period_ms: 60_000,
            burst: None,
            verification_ms: 60_001,
        }
    }

    async fn total(conn: &mut AsyncPgConnection) -> i64 {
        sql_query(
            "SELECT COALESCE(SUM(consumed),0)::bigint AS consumed FROM capability_quota_counters",
        )
        .get_result::<ConsumedRow>(conn)
        .await
        .unwrap()
        .consumed
    }

    #[tokio::test]
    async fn controller_and_agent_reservations_are_atomic_and_retries_count_once() {
        let database = TestDatabase::lease().await;
        let mut conn = database.pool().get().await.unwrap();
        sql_query("BEGIN").execute(&mut conn).await.unwrap();
        let parent = reservation(1, "controller", 1);
        let agent = reservation(2, "agent-a", 5);
        let combined = [parent.clone(), agent.clone()];
        assert!(
            try_reserve_in_connection(&mut conn, &combined, "first")
                .await
                .unwrap()
        );
        assert!(
            try_reserve_in_connection(&mut conn, &combined, "first")
                .await
                .unwrap()
        );
        assert_eq!(total(&mut conn).await, 2);
        // Another Agent cannot create a fresh parent counter.
        assert!(
            !try_reserve_in_connection(
                &mut conn,
                &[parent, reservation(3, "agent-b", 5)],
                "second"
            )
            .await
            .unwrap()
        );
        assert_eq!(total(&mut conn).await, 2);
        // Exhausting the Agent's tighter quota rolls back the parent as well.
        assert!(
            !try_reserve_in_connection(
                &mut conn,
                &[
                    reservation(4, "controller", 5),
                    reservation(5, "agent-c", 0)
                ],
                "third"
            )
            .await
            .unwrap()
        );
        assert_eq!(total(&mut conn).await, 2);
        sql_query("ROLLBACK").execute(&mut conn).await.unwrap();
        assert_eq!(total(&mut conn).await, 0);
    }

    #[tokio::test]
    async fn sibling_agents_cannot_both_reserve_the_last_controller_unit() {
        let database = TestDatabase::lease().await;
        let pool = database.pool().clone();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let mut tasks = Vec::new();
        for seed in [2, 3] {
            let pool = pool.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                let mut conn = pool.get().await.unwrap();
                sql_query("BEGIN").execute(&mut conn).await.unwrap();
                barrier.wait().await;
                let admitted = try_reserve_in_connection(
                    &mut conn,
                    &[
                        reservation(1, "controller", 1),
                        reservation(seed, "agent", 5),
                    ],
                    &format!("operation-{seed}"),
                )
                .await
                .unwrap();
                sql_query("COMMIT").execute(&mut conn).await.unwrap();
                admitted
            }));
        }
        let mut admitted = 0;
        for task in tasks {
            admitted += usize::from(task.await.unwrap());
        }
        assert_eq!(admitted, 1);
        assert_eq!(total(&mut pool.get().await.unwrap()).await, 2);
    }
}
