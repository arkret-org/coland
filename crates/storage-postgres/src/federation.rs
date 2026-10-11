use arkret_wire::{ActorId, DidCoreId};
use serde_json::Value;

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, ExistsRow, FederationOperationsStore,
    FederationOutboxClaim, FederationOutboxDeadLetterRecord, FederationOutboxOutcome,
    FederationOutboxPolicyResolution, FederationOutboxRecord, FederationOutboxRequeue,
    FederationOutboxState, FederationOutboxStateDepth, FederationOutboxStore,
    FederationOutboxTransition, Integer, JsonPayloadRow, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, ProjectedEventOperation,
    QueryableByName, RunQueryDsl, Text, Timestamptz, async_trait,
    classify_federation_outbox_completion, ids, pg_conn, sql_query, sql_types,
};

/// Every column of `federation_outbox`, aliased to the record field names.
pub(crate) const OUTBOX_COLUMNS: &str = "id, peer_id, peer_url, endpoint, idempotency_key, \
     payload_json, coalescing_key, coalescing_position, state, leased_from_state, realm_fanout, attempts, semantic_attempts, next_attempt_at, last_http_status, \
     last_error_code, last_response_excerpt, lease_owner, lease_token, lease_expires_at, \
     policy_version, supersedes_outbox_id, created_at, completed_at";

/// Qualify the shared outbox projection when it is used in a JOIN.
///
/// PostgreSQL correctly rejects bare `id`, `state`, and timestamp columns once
/// the canonical Event/link tables join the outbox. Keeping the aliases here
/// also prevents the standalone and joined row decoders from drifting.
pub(crate) fn qualified_outbox_columns(alias: &str) -> String {
    OUTBOX_COLUMNS
        .split(',')
        .map(|column| format!("{alias}.{}", column.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

const DEAD_LETTER_COLUMNS: &str = "id, outbox_id, peer_id, endpoint, idempotency_key, last_http_status, attempts, \
     response_excerpt, reason, failed_at, requeued_outbox_id, requeued_by, requeue_reason, \
     requeue_request_digest, requeued_at";

// G3.S0 — Postgres-backed durable outbound federation HTTP delivery queue.
// Mirrors `MemoryFederationOutboxStore`. The `(peer_id,
// idempotency_key)` UNIQUE INDEX in the migration is what makes
// `enqueue` structurally idempotent across worker restarts; we catch
// the conflict here and return Ok(false).
pub struct PgFederationOutboxStore {
    pub pool: PgPool,
}

/// Insert one outbox row on an existing connection or transaction. Shared with
/// the atomic Event-batch commits in `events.rs`, which must write the delivery
/// intent inside the same transaction as the Events.
pub(crate) async fn insert_federation_outbox_row(
    conn: &mut AsyncPgConnection,
    record: &FederationOutboxRecord,
) -> PersistenceResult<usize> {
    record
        .validate_shape()
        .map_err(|error| PersistenceError::Conflict(format!("schema_violation: {error}")))?;
    sql_query(
        "INSERT INTO federation_outbox \
         (id, peer_id, peer_url, endpoint, idempotency_key, payload_json, coalescing_key, coalescing_position, state, leased_from_state, realm_fanout, attempts, \
          semantic_attempts, next_attempt_at, last_http_status, last_error_code, \
          last_response_excerpt, lease_owner, lease_token, lease_expires_at, policy_version, \
          supersedes_outbox_id, created_at, completed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, \
          $19, $20, $21, $22, $23, $24) \
         ON CONFLICT (peer_id, idempotency_key) DO NOTHING",
    )
    .bind::<Text, _>(&record.id)
    .bind::<Text, _>(record.peer_id.as_str())
    .bind::<Nullable<Text>, _>(record.peer_url.as_deref())
    .bind::<Text, _>(&record.endpoint)
    .bind::<Text, _>(&record.idempotency_key)
    .bind::<Text, _>(&record.payload_json)
    .bind::<Nullable<Text>, _>(record.coalescing_key.as_deref())
    .bind::<Nullable<BigInt>, _>(record.coalescing_position)
    .bind::<Text, _>(record.state.as_str())
    .bind::<Nullable<Text>, _>(
        record
            .leased_from_state
            .map(FederationOutboxState::as_str),
    )
    .bind::<Nullable<Jsonb>, _>(
        record
            .realm_fanout
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!("realm fanout encode: {error}"))
            })?,
    )
    .bind::<Integer, _>(record.attempts)
    .bind::<Integer, _>(record.semantic_attempts)
    .bind::<BigInt, _>(record.next_attempt_at)
    .bind::<Nullable<Integer>, _>(record.last_http_status)
    .bind::<Nullable<Text>, _>(record.last_error_code.as_deref())
    .bind::<Nullable<Text>, _>(record.last_response_excerpt.as_deref())
    .bind::<Nullable<Text>, _>(record.lease_owner.as_deref())
    .bind::<Nullable<Text>, _>(record.lease_token.as_deref())
    .bind::<Nullable<BigInt>, _>(record.lease_expires_at)
    .bind::<Nullable<Text>, _>(record.policy_version.as_deref())
    .bind::<Nullable<Text>, _>(record.supersedes_outbox_id.as_deref())
    .bind::<BigInt, _>(record.created_at)
    .bind::<Nullable<BigInt>, _>(record.completed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)
}

/// Enqueue one outbox row on a caller-owned connection.
///
/// The Event commit unit of work calls this so the delivery row becomes
/// visible in the same transaction that appended the Event's `RealmCommit`:
/// a rolled-back commit leaves nothing for a federation worker to pick up.
pub(crate) async fn enqueue_federation_outbox_in_connection(
    conn: &mut AsyncPgConnection,
    record: &FederationOutboxRecord,
) -> Result<bool, PgTransactionError> {
    let record = record.clone();
    let Some(coalescing_key) = record.coalescing_key.as_deref() else {
        return Ok(insert_federation_outbox_row(conn, &record).await? > 0);
    };
    let coalescing_position = record.coalescing_position.ok_or_else(|| {
        PersistenceError::Conflict(
            "schema_violation: coalescing lane omits its position".to_owned(),
        )
    })?;
    // The advisory-lock key is bound as TEXT, and PostgreSQL rejects
    // NUL in text; \u{1f} keeps the two halves unambiguous.
    let lock_key = format!("{}\u{1f}{coalescing_key}", record.peer_id);
    sql_query("SELECT true AS present FROM pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(&lock_key)
        .get_result::<ExistsRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;

    let duplicate = sql_query(
        "SELECT true AS present FROM federation_outbox \
                 WHERE peer_id = $1 AND idempotency_key = $2 LIMIT 1",
    )
    .bind::<Text, _>(record.peer_id.as_str())
    .bind::<Text, _>(&record.idempotency_key)
    .get_result::<ExistsRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .is_some();
    if duplicate {
        return Ok(false);
    }

    let active = sql_query(
        "SELECT id, coalescing_position FROM federation_outbox \
                 WHERE peer_id = $1 AND coalescing_key = $2 \
                   AND state IN ('pending', 'pending_route', 'leased', 'policy_suppressed') \
                 ORDER BY coalescing_position DESC LIMIT 1 FOR UPDATE",
    )
    .bind::<Text, _>(record.peer_id.as_str())
    .bind::<Text, _>(coalescing_key)
    .get_result::<ActiveCoalescingLaneRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let mut record = record;
    if let Some(active) = active {
        if active.coalescing_position >= coalescing_position {
            return Ok(false);
        }
        sql_query(
            "UPDATE federation_outbox SET state = 'superseded', completed_at = $2, \
                     next_attempt_at = $2, lease_owner = NULL, lease_token = NULL, \
                     lease_expires_at = NULL, leased_from_state = NULL, policy_version = NULL \
                     WHERE id = $1",
        )
        .bind::<Text, _>(&active.id)
        .bind::<BigInt, _>(record.created_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        record.supersedes_outbox_id = Some(active.id);
    }
    Ok(insert_federation_outbox_row(conn, &record).await? > 0)
}

#[async_trait]
impl FederationOutboxStore for PgFederationOutboxStore {
    async fn historical_content_holders_for_actor(
        &self,
        actor: &ActorId,
    ) -> PersistenceResult<Vec<DidCoreId>> {
        #[derive(QueryableByName)]
        struct Peer {
            #[diesel(sql_type = Text)]
            peer_id: String,
        }
        let mut conn = pg_conn(&self.pool).await?;
        let peers = sql_query(
            "SELECT DISTINCT o.peer_id FROM federation_outbox o \
            JOIN event_federation_outbox link ON link.outbox_id=o.id \
            JOIN canonical_events e ON e.pk=link.event_pk \
            WHERE e.actor_id=$1 AND e.state='committed' AND o.realm_fanout IS NOT NULL \
            AND (o.state='delivered' OR o.attempts>0) ORDER BY o.peer_id",
        )
        .bind::<Text, _>(actor.to_string())
        .load::<Peer>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        peers
            .into_iter()
            .map(|peer| DidCoreId::new(peer.peer_id).map_err(PersistenceError::database))
            .collect()
    }

    async fn erasure_receipt_feedback(
        &self,
        receipt: &arkret_models_collaboration::governance::erasure::ErasureReceipt,
    ) -> PersistenceResult<
        Vec<(
            arkret_models_collaboration::governance::erasure::ErasureReceiptPackage,
            chrono::DateTime<chrono::Utc>,
        )>,
    > {
        #[derive(QueryableByName)]
        struct Feedback {
            #[diesel(sql_type = Jsonb)]
            package: Value,
            #[diesel(sql_type = Timestamptz)]
            received_at: chrono::DateTime<chrono::Utc>,
        }
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT response_body->'package' AS package,created_at AS received_at \
            FROM idempotency_keys WHERE operation_id='coland://internal/idempotency' \
            AND idempotency_key LIKE 'erasure-receipt:lookup:%' \
            AND response_body#>>'{package,receipt,issuer_id}'<>$1 \
            AND response_body#>'{package,receipt,trigger}'=$2 \
            AND response_body#>'{package,receipt,subject}'=$3 \
            AND response_body#>'{package,receipt,scope}'=$4 \
            AND authenticated_actor=$5 AND response_body#>>'{acceptance,receiver_id}'=$1",
        )
        .bind::<Text, _>(receipt.issuer_id.as_str())
        .bind::<Jsonb, _>(
            serde_json::to_value(&receipt.trigger).map_err(PersistenceError::database)?,
        )
        .bind::<Jsonb, _>(
            serde_json::to_value(&receipt.subject).map_err(PersistenceError::database)?,
        )
        .bind::<Jsonb, _>(serde_json::to_value(&receipt.scope).map_err(PersistenceError::database)?)
        .bind::<Jsonb, _>(
            serde_json::to_value(ActorId::service(receipt.issuer_id.clone()))
                .map_err(PersistenceError::database)?,
        )
        .load::<Feedback>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    serde_json::from_value(row.package).map_err(PersistenceError::database)?,
                    row.received_at,
                ))
            })
            .collect()
    }

    async fn erasure_receipt_deliveries(
        &self,
        receipt_id: &str,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(format!(
            "SELECT {OUTBOX_COLUMNS} FROM federation_outbox \
            WHERE endpoint='/_arkret/peer/erasure-receipts' \
              AND payload_json::jsonb#>>'{{package,receipt,receipt_id}}'=$1 ORDER BY peer_id"
        ))
        .bind::<Text, _>(receipt_id)
        .load::<FederationOutboxRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(FederationOutboxRecord::try_from)
        .collect()
    }

    async fn historical_content_holders(
        &self,
        realm_ids: &[arkret_wire::RealmId],
    ) -> PersistenceResult<Vec<DidCoreId>> {
        #[derive(QueryableByName)]
        struct Peer {
            #[diesel(sql_type = Text)]
            peer_id: String,
        }
        let realms: Vec<_> = realm_ids.iter().map(|id| id.as_str().to_owned()).collect();
        let mut conn = pg_conn(&self.pool).await?;
        let peers = sql_query(
            "SELECT DISTINCT o.peer_id FROM federation_outbox o \
             JOIN event_federation_outbox link ON link.outbox_id=o.id \
             JOIN canonical_events e ON e.pk=link.event_pk \
             WHERE e.realm_id=ANY($1) AND e.state='committed' \
               AND o.realm_fanout IS NOT NULL \
               AND (o.state='delivered' OR o.attempts>0) ORDER BY o.peer_id",
        )
        .bind::<sql_types::Array<Text>, _>(realms)
        .load::<Peer>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        peers
            .into_iter()
            .map(|peer| DidCoreId::new(peer.peer_id).map_err(PersistenceError::database))
            .collect()
    }

    async fn enqueue(&self, record: &FederationOutboxRecord) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let record = record.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            enqueue_federation_outbox_in_connection(conn, &record).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn claim_due(
        &self,
        claim: &FederationOutboxClaim,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        // Select-and-own in one statement. `FOR UPDATE SKIP LOCKED` is what
        // keeps two replicas off the same row; an expired `leased` row is
        // reclaimable so a crashed worker never strands its batch.
        let rows = sql_query(format!(
            // The CTE aliases its key to `claim_id` so the `RETURNING` list can
            // name the row's own columns unqualified without colliding with the
            // joined CTE's `id`.
            "WITH claimed AS ( \
                 SELECT id AS claim_id FROM federation_outbox \
                 WHERE next_attempt_at <= $1 \
                   AND (state IN ('pending', 'pending_route') \
                        OR (state = 'leased' AND COALESCE(lease_expires_at, 0) <= $1)) \
                 ORDER BY next_attempt_at ASC, id ASC \
                 LIMIT $2 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             UPDATE federation_outbox AS outbox SET \
                 leased_from_state = CASE WHEN outbox.state = 'leased' THEN outbox.leased_from_state ELSE outbox.state END, \
                 state = 'leased', \
                 lease_owner = $3, \
                 lease_token = $4, \
                 lease_expires_at = $1 + $5 \
             FROM claimed \
             WHERE outbox.id = claimed.claim_id \
             RETURNING {OUTBOX_COLUMNS}"
        ))
        .bind::<BigInt, _>(claim.now_unix_secs)
        .bind::<BigInt, _>(claim.limit as i64)
        .bind::<Text, _>(&claim.lease_owner)
        .bind::<Text, _>(&claim.lease_token)
        .bind::<BigInt, _>(claim.lease_duration_secs)
        .load::<FederationOutboxRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let mut records = rows
            .into_iter()
            .map(FederationOutboxRecord::try_from)
            .collect::<PersistenceResult<Vec<_>>>()?;
        records.sort_by(|left, right| {
            (left.next_attempt_at, left.id.as_str())
                .cmp(&(right.next_attempt_at, right.id.as_str()))
        });
        Ok(records)
    }

    async fn complete(&self, transition: &FederationOutboxTransition) -> PersistenceResult<bool> {
        let transition = transition.clone();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            if let FederationOutboxOutcome::Superseded(successor) = &transition.outcome
                && let Some(coalescing_key) = successor.coalescing_key.as_deref()
            {
                // Same TEXT-bound advisory-lock key as `enqueue`: no NUL.
                let lock_key = format!("{}\u{1f}{coalescing_key}", successor.peer_id);
                sql_query(
                    "SELECT true AS present FROM pg_advisory_xact_lock(hashtextextended($1, 0))",
                )
                .bind::<Text, _>(&lock_key)
                .get_result::<ExistsRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            }
            let row_kind = sql_query(
                "SELECT realm_fanout IS NOT NULL AS present FROM federation_outbox \
                 WHERE id = $1 AND lease_token = $2 FOR UPDATE",
            )
            .bind::<Text, _>(&transition.id)
            .bind::<Text, _>(&transition.lease_token)
            .get_result::<ExistsRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            let Some(row_kind) = row_kind else {
                return Ok(false);
            };
            let completion =
                classify_federation_outbox_completion(row_kind.present, &transition)
                    .map_err(PgTransactionError::from)?;
            // The lease-token predicate is the concurrency guard: a stale
            // holder's late response updates zero rows and is dropped.
            let updated = sql_query(
                "UPDATE federation_outbox SET \
                 state = $3, attempts = $4, semantic_attempts = $5, next_attempt_at = $6, \
                 last_http_status = $7, last_error_code = $8, last_response_excerpt = $9, \
                 lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, leased_from_state = NULL, \
                 policy_version = $10, completed_at = $11 \
                 WHERE id = $1 AND lease_token = $2",
            )
            .bind::<Text, _>(&transition.id)
            .bind::<Text, _>(&transition.lease_token)
            .bind::<Text, _>(completion.state.as_str())
            .bind::<Integer, _>(transition.attempts)
            .bind::<Integer, _>(transition.semantic_attempts)
            .bind::<BigInt, _>(completion.next_attempt_at)
            .bind::<Nullable<Integer>, _>(transition.last_http_status)
            .bind::<Nullable<Text>, _>(transition.last_error_code.as_deref())
            .bind::<Nullable<Text>, _>(transition.last_response_excerpt.as_deref())
            .bind::<Nullable<Text>, _>(completion.policy_version.as_deref())
            .bind::<Nullable<BigInt>, _>(completion.completed_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            if updated == 0 {
                return Ok(false);
            }
            match &transition.outcome {
                FederationOutboxOutcome::DeadLettered(record) => {
                    insert_dead_letter_row(conn, record).await?;
                }
                FederationOutboxOutcome::Superseded(successor) => {
                    insert_federation_outbox_row(conn, successor).await?;
                }
                _ => {}
            }
            Ok(true)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn policy_suppressed_stale(
        &self,
        current_policy_version: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(format!(
            "SELECT {OUTBOX_COLUMNS} FROM federation_outbox \
             WHERE state = 'policy_suppressed' \
               AND COALESCE(policy_version, '') <> $1 \
             ORDER BY created_at ASC, id ASC LIMIT $2"
        ))
        .bind::<Text, _>(current_policy_version)
        .bind::<BigInt, _>(limit as i64)
        .load::<FederationOutboxRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(FederationOutboxRecord::try_from)
            .collect()
    }

    async fn resolve_policy_suppressed(
        &self,
        id: &str,
        resolution: &FederationOutboxPolicyResolution,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let updated = match resolution {
            FederationOutboxPolicyResolution::Release { next_attempt_at } => {
                sql_query(
                    "UPDATE federation_outbox SET \
                 state = 'pending', next_attempt_at = $2, policy_version = NULL, \
                 last_error_code = NULL, completed_at = NULL \
                 WHERE id = $1 AND state = 'policy_suppressed'",
                )
                .bind::<Text, _>(id)
                .bind::<BigInt, _>(*next_attempt_at)
                .execute(&mut *conn)
                .await
            }
            FederationOutboxPolicyResolution::Repin { policy_version } => {
                sql_query(
                    "UPDATE federation_outbox SET policy_version = $2 \
                 WHERE id = $1 AND state = 'policy_suppressed'",
                )
                .bind::<Text, _>(id)
                .bind::<Text, _>(policy_version)
                .execute(&mut *conn)
                .await
            }
        }
        .map_err(PersistenceError::database)?;
        Ok(updated > 0)
    }

    async fn get(&self, id: &str) -> PersistenceResult<Option<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {OUTBOX_COLUMNS} FROM federation_outbox WHERE id = $1"
        ))
        .bind::<Text, _>(id)
        .get_result::<FederationOutboxRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(FederationOutboxRecord::try_from)
        .transpose()
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(format!(
            "SELECT {OUTBOX_COLUMNS} FROM federation_outbox ORDER BY created_at ASC, id ASC"
        ))
        .load::<FederationOutboxRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(FederationOutboxRecord::try_from)
            .collect()
    }

    async fn list_by_state(
        &self,
        state: FederationOutboxState,
        limit: usize,
    ) -> PersistenceResult<Vec<FederationOutboxRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(format!(
            "SELECT {OUTBOX_COLUMNS} FROM federation_outbox WHERE state = $1 \
             ORDER BY created_at DESC, id DESC LIMIT $2"
        ))
        .bind::<Text, _>(state.as_str())
        .bind::<BigInt, _>(limit as i64)
        .load::<FederationOutboxRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(FederationOutboxRecord::try_from)
            .collect()
    }

    async fn state_depth(&self) -> PersistenceResult<Vec<FederationOutboxStateDepth>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT state, peer_id, COUNT(*) AS depth, MIN(created_at) AS oldest_created_at \
             FROM federation_outbox GROUP BY state, peer_id ORDER BY state ASC, peer_id ASC",
        )
        .load::<FederationOutboxStateDepthRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                Ok(FederationOutboxStateDepth {
                    state: FederationOutboxState::parse(&row.state).ok_or_else(|| {
                        PersistenceError::Internal(format!(
                            "unknown federation outbox state {}",
                            row.state
                        ))
                    })?,
                    peer_id: row.peer_id,
                    depth: row.depth,
                    oldest_created_at: row.oldest_created_at,
                })
            })
            .collect()
    }

    async fn dead_letter(
        &self,
        id: &str,
    ) -> PersistenceResult<Option<FederationOutboxDeadLetterRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(format!(
            "SELECT {DEAD_LETTER_COLUMNS} FROM federation_outbox_dead_letter WHERE id = $1"
        ))
        .bind::<Text, _>(id)
        .get_result::<FederationOutboxDeadLetterRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(FederationOutboxDeadLetterRecord::try_from)
        .transpose()
    }

    async fn dead_letters_snapshot(
        &self,
    ) -> PersistenceResult<Vec<FederationOutboxDeadLetterRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(format!(
            "SELECT {DEAD_LETTER_COLUMNS} FROM federation_outbox_dead_letter \
             ORDER BY failed_at ASC, id ASC"
        ))
        .load::<FederationOutboxDeadLetterRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(FederationOutboxDeadLetterRecord::try_from)
            .collect()
    }

    async fn requeue_dead_letter(
        &self,
        command: &FederationOutboxRequeue,
    ) -> PersistenceResult<bool> {
        let command = command.clone();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // Claim the dead letter first: `requeued_outbox_id IS NULL` makes
            // the replay single-shot even under concurrent operators.
            let stamped = sql_query(
                "UPDATE federation_outbox_dead_letter SET \
                 requeued_outbox_id = $2, requeued_by = $3, requeue_reason = $4, \
                 requeue_request_digest = $5, requeued_at = $6 \
                 WHERE id = $1 AND requeued_outbox_id IS NULL",
            )
            .bind::<Text, _>(&command.dead_letter_id)
            .bind::<Text, _>(&command.record.id)
            .bind::<Text, _>(&command.operator)
            .bind::<Text, _>(&command.reason)
            .bind::<Text, _>(&command.request_digest)
            .bind::<BigInt, _>(command.requeued_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            if stamped == 0 {
                return Ok(false);
            }
            if insert_federation_outbox_row(conn, &command.record).await? == 0 {
                return Err(PersistenceError::Conflict(
                    "duplicate_conflict: federation outbox requeue key already enqueued".to_owned(),
                )
                .into());
            }
            Ok(true)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

async fn insert_dead_letter_row(
    conn: &mut AsyncPgConnection,
    record: &FederationOutboxDeadLetterRecord,
) -> PersistenceResult<()> {
    sql_query(
        "INSERT INTO federation_outbox_dead_letter \
         (id, outbox_id, peer_id, endpoint, idempotency_key, last_http_status, attempts, \
          response_excerpt, reason, failed_at, requeued_outbox_id, requeued_by, requeue_reason, \
          requeue_request_digest, requeued_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind::<Text, _>(&record.id)
    .bind::<Text, _>(&record.outbox_id)
    .bind::<Text, _>(record.peer_id.as_str())
    .bind::<Text, _>(&record.endpoint)
    .bind::<Text, _>(&record.idempotency_key)
    .bind::<Nullable<Integer>, _>(record.last_http_status)
    .bind::<Integer, _>(record.attempts)
    .bind::<Nullable<Text>, _>(record.response_excerpt.as_deref())
    .bind::<Text, _>(&record.reason)
    .bind::<BigInt, _>(record.failed_at)
    .bind::<Nullable<Text>, _>(record.requeued_outbox_id.as_deref())
    .bind::<Nullable<Text>, _>(record.requeued_by.as_deref())
    .bind::<Nullable<Text>, _>(record.requeue_reason.as_deref())
    .bind::<Nullable<Text>, _>(record.requeue_request_digest.as_deref())
    .bind::<Nullable<BigInt>, _>(record.requeued_at)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(PersistenceError::database)
}
pub struct PgFederationOperationsStore {
    pub pool: PgPool,
}
#[async_trait]
impl FederationOperationsStore for PgFederationOperationsStore {
    async fn append(&self, operation: ProjectedEventOperation) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let payload = serde_json::to_value(&operation).map_err(|error| {
            PersistenceError::Internal(format!("federation operation serialize: {error}"))
        })?;
        let object_id = operation.object_id.clone();
        let operation_kind = serde_json::to_value(&operation.operation_kind)
            .ok()
            .and_then(|v| v.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "create".to_owned());
        let operation_id_uuid =
            ids::typed_uuid_part_expect_internal(operation.operation_id.as_str());
        crate::realm_identity::ensure_realm_pk(&mut conn, operation.realm_id.as_str()).await?;
        sql_query(
            "INSERT INTO federation_operations \
             (id, realm_id, object_kind, object_id, operation_kind, payload, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind::<sql_types::Uuid, _>(operation_id_uuid)
        .bind::<Text, _>(operation.realm_id.as_str())
        .bind::<Text, _>(operation.event_kind.as_str())
        .bind::<Nullable<Text>, _>(&object_id)
        .bind::<Text, _>(&operation_kind)
        .bind::<Jsonb, _>(&payload)
        .bind::<Timestamptz, _>(operation.created_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn contains(&self, operation_id: &str) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let operation_id_uuid = ids::typed_uuid_part_expect_internal(operation_id);
        sql_query("SELECT EXISTS(SELECT 1 FROM federation_operations WHERE id = $1) AS present")
            .bind::<sql_types::Uuid, _>(operation_id_uuid)
            .get_result::<ExistsRow>(&mut *conn)
            .await
            .map(|row| row.present)
            .map_err(PersistenceError::database)
    }

    async fn list_for_realm(
        &self,
        realm_id: &str,
    ) -> PersistenceResult<Vec<ProjectedEventOperation>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows: Vec<JsonPayloadRow> = sql_query(
            "SELECT payload FROM federation_operations \
             WHERE realm_id = $1 ORDER BY created_at ASC, id ASC",
        )
        .bind::<Text, _>(realm_id)
        .load::<JsonPayloadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                serde_json::from_value::<ProjectedEventOperation>(row.payload).map_err(|error| {
                    PersistenceError::Internal(format!("federation operation deserialize: {error}"))
                })
            })
            .collect()
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<ProjectedEventOperation>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows: Vec<JsonPayloadRow> = sql_query(
            "SELECT payload FROM federation_operations \
             ORDER BY created_at ASC, id ASC",
        )
        .load::<JsonPayloadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                serde_json::from_value::<ProjectedEventOperation>(row.payload).map_err(|error| {
                    PersistenceError::Internal(format!("federation operation deserialize: {error}"))
                })
            })
            .collect()
    }
}
// ── Pg-backed wire-facing sub-stores ─────────────────────────────────────
//
// ModerationStore / PresenceStore / WebvhStore. Each
// follows the same pattern: a typed-column header (extracted from the JSON
// payload where applicable) plus the full canonical envelope in a JSONB
// column. The trait surface itself is the architectural contract; the
// Pg + Memory backends both implement it identically.

#[derive(QueryableByName)]
struct ActiveCoalescingLaneRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = BigInt)]
    coalescing_position: i64,
}

#[derive(QueryableByName)]
pub(crate) struct FederationOutboxRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    peer_id: DidCoreId,
    #[diesel(sql_type = Nullable<Text>)]
    peer_url: Option<String>,
    #[diesel(sql_type = Text)]
    endpoint: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Text)]
    payload_json: String,
    #[diesel(sql_type = Nullable<Text>)]
    coalescing_key: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    coalescing_position: Option<i64>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Text>)]
    leased_from_state: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    realm_fanout: Option<serde_json::Value>,
    #[diesel(sql_type = Integer)]
    attempts: i32,
    #[diesel(sql_type = Integer)]
    semantic_attempts: i32,
    #[diesel(sql_type = BigInt)]
    next_attempt_at: i64,
    #[diesel(sql_type = Nullable<Integer>)]
    last_http_status: Option<i32>,
    #[diesel(sql_type = Nullable<Text>)]
    last_error_code: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    last_response_excerpt: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    lease_owner: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    lease_token: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    lease_expires_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    policy_version: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    supersedes_outbox_id: Option<String>,
    #[diesel(sql_type = BigInt)]
    created_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    completed_at: Option<i64>,
}
impl TryFrom<FederationOutboxRow> for FederationOutboxRecord {
    type Error = PersistenceError;

    fn try_from(row: FederationOutboxRow) -> Result<Self, Self::Error> {
        let state = FederationOutboxState::parse(&row.state).ok_or_else(|| {
            PersistenceError::Internal(format!(
                "stored federation outbox state is invalid: {:?}",
                row.state
            ))
        })?;
        let leased_from_state = row
            .leased_from_state
            .as_deref()
            .map(|state| {
                FederationOutboxState::parse(state).ok_or_else(|| {
                    PersistenceError::Internal(format!(
                        "stored federation outbox leased_from_state is invalid: {state:?}"
                    ))
                })
            })
            .transpose()?;
        let realm_fanout = row
            .realm_fanout
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "stored Realm fanout binding is invalid: {error}"
                ))
            })?;
        let record = Self {
            id: row.id,
            peer_id: row.peer_id,
            peer_url: row.peer_url,
            endpoint: row.endpoint,
            idempotency_key: row.idempotency_key,
            payload_json: row.payload_json,
            coalescing_key: row.coalescing_key,
            coalescing_position: row.coalescing_position,
            state,
            leased_from_state,
            realm_fanout,
            attempts: row.attempts,
            semantic_attempts: row.semantic_attempts,
            next_attempt_at: row.next_attempt_at,
            last_http_status: row.last_http_status,
            last_error_code: row.last_error_code,
            last_response_excerpt: row.last_response_excerpt,
            lease_owner: row.lease_owner,
            lease_token: row.lease_token,
            lease_expires_at: row.lease_expires_at,
            policy_version: row.policy_version,
            supersedes_outbox_id: row.supersedes_outbox_id,
            created_at: row.created_at,
            completed_at: row.completed_at,
        };
        record.validate_shape().map_err(|error| {
            PersistenceError::Internal(format!("stored federation outbox row is invalid: {error}"))
        })?;
        Ok(record)
    }
}
#[derive(QueryableByName)]
struct FederationOutboxStateDepthRow {
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Text)]
    peer_id: DidCoreId,
    #[diesel(sql_type = BigInt)]
    depth: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    oldest_created_at: Option<i64>,
}
#[derive(QueryableByName)]
struct FederationOutboxDeadLetterRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    outbox_id: String,
    #[diesel(sql_type = Text)]
    peer_id: DidCoreId,
    #[diesel(sql_type = Text)]
    endpoint: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Nullable<Integer>)]
    last_http_status: Option<i32>,
    #[diesel(sql_type = Integer)]
    attempts: i32,
    #[diesel(sql_type = Nullable<Text>)]
    response_excerpt: Option<String>,
    #[diesel(sql_type = Text)]
    reason: String,
    #[diesel(sql_type = BigInt)]
    failed_at: i64,
    #[diesel(sql_type = Nullable<Text>)]
    requeued_outbox_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    requeued_by: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    requeue_reason: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    requeue_request_digest: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    requeued_at: Option<i64>,
}
impl TryFrom<FederationOutboxDeadLetterRow> for FederationOutboxDeadLetterRecord {
    type Error = PersistenceError;

    fn try_from(row: FederationOutboxDeadLetterRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            outbox_id: row.outbox_id,
            peer_id: row.peer_id,
            endpoint: row.endpoint,
            idempotency_key: row.idempotency_key,
            last_http_status: row.last_http_status,
            attempts: row.attempts,
            response_excerpt: row.response_excerpt,
            reason: row.reason,
            failed_at: row.failed_at,
            requeued_outbox_id: row.requeued_outbox_id,
            requeued_by: row.requeued_by,
            requeue_reason: row.requeue_reason,
            requeue_request_digest: row.requeue_request_digest,
            requeued_at: row.requeued_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joined_outbox_projection_qualifies_every_source_column() {
        let columns = qualified_outbox_columns("outbox");

        assert!(columns.starts_with("outbox.id, outbox.peer_id"));
        assert!(columns.contains(", outbox.state,"));
        assert!(columns.ends_with("outbox.completed_at"));
        assert_eq!(
            columns.split(',').count(),
            OUTBOX_COLUMNS.split(',').count()
        );
    }
}
