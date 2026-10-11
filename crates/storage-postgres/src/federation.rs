use arkret_wire::{ActorId, DidCoreId, Hash};
use serde_json::Value;

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Binary, ExistsRow,
    FederationForkNormalizationScope, FederationFrontierConfirmedEvidenceRecord,
    FederationFrontierExchangeRecord, FederationFrontierExchangeStore,
    FederationFrontierReductionCheckpoint, FederationFrontierResolutionRecord,
    FederationOperationsStore, FederationOutboxClaim, FederationOutboxDeadLetterRecord,
    FederationOutboxOutcome, FederationOutboxPolicyResolution, FederationOutboxRecord,
    FederationOutboxRequeue, FederationOutboxState, FederationOutboxStateDepth,
    FederationOutboxStore, FederationOutboxTransition, Integer, JsonPayloadRow, Jsonb, Nullable,
    OptionalExtension, PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    ProjectedEventOperation, QueryableByName, RunQueryDsl, Text, Timestamptz, async_trait,
    classify_federation_outbox_completion, frontier_exchange_failure_record,
    frontier_exchange_success_record, ids, pg_conn, sql_query, sql_types,
};

/// `federation_fork_normalization` columns for one verdict.
///
/// Exactly one subject shape is populated, matching the table's own CHECK. Both
/// Event ids are stored as the 33-octet identity token rather than the wire
/// string so the view can compare them against `canonical_events.id` directly,
/// and a malformed id is rejected here rather than silently never matching.
struct NormalizationScopeColumns {
    actor_id: Option<String>,
    actor_seq: Option<i64>,
    winner_event_id: Option<Vec<u8>>,
    collision_event_id: Option<Vec<u8>>,
    winner_canonical_bytes: Option<Vec<u8>>,
    winner_sealed_at: Option<i64>,
}

fn normalization_event_id(event_id: &str) -> PersistenceResult<Vec<u8>> {
    ids::parse_event_id(event_id)
        .map(|id| id.to_vec())
        .ok_or_else(|| {
            PersistenceError::SchemaViolation(format!(
                "malformed fork resolution Event id: {event_id:?}"
            ))
        })
}

fn normalization_scope_columns(
    scope: &FederationForkNormalizationScope,
) -> PersistenceResult<NormalizationScopeColumns> {
    Ok(match scope {
        FederationForkNormalizationScope::SiblingPosition {
            actor_id,
            actor_seq,
            winner_event_id,
        } => NormalizationScopeColumns {
            actor_id: Some(actor_id.clone()),
            actor_seq: Some(i64::try_from(*actor_seq).map_err(|_| {
                PersistenceError::SchemaViolation(
                    "fork resolution actor_seq exceeds i64 range".to_owned(),
                )
            })?),
            winner_event_id: winner_event_id
                .as_deref()
                .map(normalization_event_id)
                .transpose()?,
            collision_event_id: None,
            winner_canonical_bytes: None,
            winner_sealed_at: None,
        },
        FederationForkNormalizationScope::EventIdCollision {
            event_id,
            winner_canonical_bytes,
            winner_sealed_at_ms,
        } => NormalizationScopeColumns {
            actor_id: None,
            actor_seq: None,
            winner_event_id: None,
            collision_event_id: Some(normalization_event_id(event_id)?),
            winner_canonical_bytes: winner_canonical_bytes.clone(),
            // The table's CHECK ties these two together, so a `canonical_winner`
            // verdict that arrived without the Seal timestamp its admission has
            // to use fails loudly instead of persisting a winner that could
            // only be admitted against a local clock.
            winner_sealed_at: *winner_sealed_at_ms,
        },
    })
}

/// Admit the winner this verdict names, in the same transaction as the verdict.
///
/// `event-auth-state-resolution.md` section 6.3.3 point 3: an accepted
/// `canonical_winner` is itself the admission authority for the winner's bytes,
/// so the Station that holds the loser adopts the winner here rather than
/// merely dropping the loser from its read surface and being left unable to
/// answer for that identity. Skipped for a sibling-position subject and for
/// `void_all`, where subtraction is the whole story.
async fn admit_adjudicated_collision_winner(
    _conn: &mut AsyncPgConnection,
    _realm_id: &str,
    _scope: &NormalizationScopeColumns,
) -> Result<(), PgTransactionError> {
    Ok(())
}

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
pub struct PgFederationFrontierExchangeStore {
    pub pool: PgPool,
}
#[async_trait]
impl FederationFrontierExchangeStore for PgFederationFrontierExchangeStore {
    async fn get(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
    ) -> PersistenceResult<Option<FederationFrontierExchangeRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT realm_id, peer_id, status, consecutive_failures, \
             last_success_at, last_failure_at, last_frontier_root, last_error, updated_at \
             FROM federation_frontier_exchange \
             WHERE realm_id = $1 AND peer_id = $2",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(peer_id.as_str())
        .get_result::<FederationFrontierExchangeRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(FederationFrontierExchangeRecord::try_from)
        .transpose()
    }

    async fn record_success(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
        frontier_root: &str,
        observed_at: i64,
    ) -> PersistenceResult<FederationFrontierExchangeRecord> {
        self.transition(realm_id, peer_id, observed_at, Some(frontier_root), None)
            .await
    }

    async fn record_failure(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
        reason: &str,
        observed_at: i64,
    ) -> PersistenceResult<FederationFrontierExchangeRecord> {
        self.transition(realm_id, peer_id, observed_at, None, Some(reason))
            .await
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<FederationFrontierExchangeRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query(
            "SELECT realm_id, peer_id, status, consecutive_failures, \
             last_success_at, last_failure_at, last_frontier_root, last_error, updated_at \
             FROM federation_frontier_exchange ORDER BY updated_at ASC, realm_id ASC, peer_id ASC",
        )
        .load::<FederationFrontierExchangeRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(FederationFrontierExchangeRecord::try_from)
            .collect()
    }

    async fn reduction_checkpoint(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
    ) -> PersistenceResult<Option<FederationFrontierReductionCheckpoint>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT realm_id, peer_id, remote_snapshot_digest, actor_set_digest, actor_id, cursor, updated_at \
             FROM federation_frontier_reduction_checkpoint WHERE realm_id = $1 AND peer_id = $2",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(peer_id.as_str())
        .get_result::<FederationFrontierReductionCheckpointRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(FederationFrontierReductionCheckpoint::try_from)
        .transpose()
    }

    async fn put_reduction_checkpoint(
        &self,
        checkpoint: &FederationFrontierReductionCheckpoint,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        crate::realm_identity::ensure_realm_pk(&mut conn, &checkpoint.realm_id).await?;
        sql_query(
            "INSERT INTO federation_frontier_reduction_checkpoint \
             (realm_id, peer_id, remote_snapshot_digest, actor_set_digest, actor_id, cursor, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (realm_id, peer_id) DO UPDATE SET \
             remote_snapshot_digest = EXCLUDED.remote_snapshot_digest, \
             actor_set_digest = EXCLUDED.actor_set_digest, actor_id = EXCLUDED.actor_id, \
             cursor = EXCLUDED.cursor, updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&checkpoint.realm_id)
        .bind::<Text, _>(checkpoint.peer_id.as_str())
        .bind::<Text, _>(&checkpoint.remote_snapshot_digest)
        .bind::<Text, _>(&checkpoint.actor_set_digest)
        .bind::<Text, _>(checkpoint.actor_id.to_string())
        .bind::<Nullable<Text>, _>(checkpoint.cursor.as_deref())
        .bind::<BigInt, _>(checkpoint.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn clear_reduction_checkpoint(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "DELETE FROM federation_frontier_reduction_checkpoint WHERE realm_id = $1 AND peer_id = $2",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(peer_id.as_str())
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }

    async fn record_confirmed_evidence(
        &self,
        evidence: &FederationFrontierConfirmedEvidenceRecord,
    ) -> PersistenceResult<()> {
        if !matches!(
            evidence.reason.as_str(),
            "witness_disagreement" | "fork_quarantine"
        ) || evidence.local_resolution_kind.is_some()
            || evidence.local_resolution_digest.is_some()
            || evidence.local_normalized_at.is_some()
            || evidence.peer_alignment_digest.is_some()
            || evidence.peer_aligned_at.is_some()
        {
            return Err(PersistenceError::SchemaViolation(
                "confirmed frontier evidence must be unresolved and use a registered reason"
                    .to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let evidence = evidence.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::realm_identity::ensure_realm_pk(conn, &evidence.realm_id).await?;
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(format!(
                    "frontier:{}:{}",
                    evidence.realm_id,
                    evidence.peer_id.as_str()
                ))
                .execute(conn)
                .await?;
            // An already-resolved scope is not re-opened by observing the same
            // evidence again; that is what the second phase settled.
            if sql_query(
                "SELECT EXISTS (SELECT 1 FROM federation_frontier_confirmed_evidence                  WHERE realm_id = $1 AND peer_id = $2 AND evidence_scope_key = $3                    AND peer_alignment_digest IS NOT NULL) AS present",
            )
            .bind::<Text, _>(&evidence.realm_id)
            .bind::<Text, _>(evidence.peer_id.as_str())
            .bind::<Text, _>(&evidence.evidence_scope_key)
            .get_result::<ExistsRow>(conn)
            .await?
            .present
            {
                return Ok(());
            }
            // The exchange row is written first because the evidence row
            // references it. First confirmed evidence can arrive for a peer this
            // Realm has never exchanged with, and losing it to a foreign-key
            // failure would drop the one signal that must fail the peer closed.
            let existing = sql_query("SELECT realm_id, peer_id, status, consecutive_failures, last_success_at, last_failure_at, last_frontier_root, last_error, updated_at FROM federation_frontier_exchange WHERE realm_id = $1 AND peer_id = $2")
                .bind::<Text, _>(&evidence.realm_id)
                .bind::<Text, _>(evidence.peer_id.as_str())
                .get_result::<FederationFrontierExchangeRow>(conn)
                .await
                .optional()?
                .map(FederationFrontierExchangeRecord::try_from)
                .transpose()?;
            let record = frontier_exchange_failure_record(
                existing,
                &evidence.realm_id,
                &evidence.peer_id,
                &evidence.reason,
                evidence.observed_at,
            );
            Self::put_record(conn, &record).await?;
            sql_query(
                "INSERT INTO federation_frontier_confirmed_evidence \
                 (realm_id, peer_id, evidence_scope_key, reason, evidence_scope, observed_at, \
                  local_resolution_kind, local_resolution_digest, local_normalized_at, \
                  peer_alignment_digest, peer_aligned_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, NULL, NULL, NULL) \
                 ON CONFLICT (realm_id, peer_id, evidence_scope_key) DO UPDATE SET \
                 reason = EXCLUDED.reason, evidence_scope = EXCLUDED.evidence_scope, \
                 observed_at = LEAST(federation_frontier_confirmed_evidence.observed_at, EXCLUDED.observed_at) \
                 WHERE federation_frontier_confirmed_evidence.peer_alignment_digest IS NULL",
            )
            .bind::<Text, _>(&evidence.realm_id)
            .bind::<Text, _>(evidence.peer_id.as_str())
            .bind::<Text, _>(&evidence.evidence_scope_key)
            .bind::<Text, _>(&evidence.reason)
            .bind::<Jsonb, _>(&evidence.evidence_scope)
            .bind::<BigInt, _>(evidence.observed_at)
            .execute(conn)
            .await?;
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn unresolved_confirmed_evidence(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
    ) -> PersistenceResult<Vec<FederationFrontierConfirmedEvidenceRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT realm_id, peer_id, evidence_scope_key, reason, evidence_scope, observed_at, \
             local_resolution_kind, local_resolution_digest, local_normalized_at, \
             peer_alignment_digest, peer_aligned_at \
             FROM federation_frontier_confirmed_evidence \
             WHERE realm_id = $1 AND peer_id = $2 AND peer_alignment_digest IS NULL \
             ORDER BY evidence_scope_key ASC",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(peer_id.as_str())
        .load::<FederationFrontierConfirmedEvidenceRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)
        .map(|rows| rows.into_iter().map(Into::into).collect())
    }

    async fn record_local_normalization(
        &self,
        resolution: &FederationFrontierResolutionRecord,
        scope: &FederationForkNormalizationScope,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let resolution = resolution.clone();
        let scope = normalization_scope_columns(scope)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(format!("authority-realm:{}", resolution.realm_id))
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            crate::realm_identity::ensure_realm_pk(conn, &resolution.realm_id).await?;
            // Replaying one accepted Event is idempotent; a second verdict for
            // a settled subject must fail rather than re-adjudicate it.
            let written = sql_query(
                "INSERT INTO federation_frontier_resolution                  (realm_id, cell_subject_key, subject, verdict, conflict_evidence_digest,                   resolution_event_digest, normalized_at)                  VALUES ($1, $2, $3, $4, $5, $6, $7)                  ON CONFLICT (realm_id, cell_subject_key) DO NOTHING",
            )
            .bind::<Text, _>(&resolution.realm_id)
            .bind::<Text, _>(&resolution.cell_subject_key)
            .bind::<Jsonb, _>(&resolution.subject)
            .bind::<Jsonb, _>(&resolution.verdict)
            .bind::<Text, _>(&resolution.conflict_evidence_digest)
            .bind::<Text, _>(&resolution.resolution_event_digest)
            .bind::<BigInt, _>(resolution.normalized_at)
            .execute(conn)
            .await?;
            if written != 1 {
                let existing = sql_query(
                    "SELECT realm_id, cell_subject_key, subject, verdict, conflict_evidence_digest,                  resolution_event_digest, normalized_at FROM federation_frontier_resolution                  WHERE realm_id = $1 AND cell_subject_key = $2",
                )
                .bind::<Text, _>(&resolution.realm_id)
                .bind::<Text, _>(&resolution.cell_subject_key)
                .get_result::<FederationFrontierResolutionRow>(conn)
                .await?;
                if FederationFrontierResolutionRecord::from(existing) != resolution {
                    return Err(PgTransactionError::Storage(PersistenceError::Conflict(
                        "failed_precondition: fork resolution subject is already settled".to_owned(),
                    )));
                }
            }
            // The read-surface subtraction rides the same transaction as the
            // verdict above. A DO NOTHING here is safe precisely because the
            // insert above already refused a second, byte-different verdict for
            // a settled subject: the columns below are a pure function of that
            // subject and verdict, so an existing row is the same row.
            sql_query(
                "INSERT INTO federation_fork_normalization \
                 (realm_id, cell_subject_key, actor_id, actor_seq, winner_event_id, \
                  collision_event_id, winner_canonical_bytes, winner_sealed_at, normalized_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (realm_id, cell_subject_key) DO NOTHING",
            )
            .bind::<Text, _>(&resolution.realm_id)
            .bind::<Text, _>(&resolution.cell_subject_key)
            .bind::<Nullable<Text>, _>(scope.actor_id.as_deref())
            .bind::<Nullable<BigInt>, _>(scope.actor_seq)
            .bind::<Nullable<Binary>, _>(scope.winner_event_id.as_deref())
            .bind::<Nullable<Binary>, _>(scope.collision_event_id.as_deref())
            .bind::<Nullable<Binary>, _>(scope.winner_canonical_bytes.as_deref())
            .bind::<Nullable<BigInt>, _>(scope.winner_sealed_at)
            .bind::<BigInt, _>(resolution.normalized_at)
            .execute(conn)
            .await?;
            admit_adjudicated_collision_winner(conn, &resolution.realm_id, &scope).await?;
            sql_query(
                "UPDATE federation_frontier_confirmed_evidence \
                 SET local_resolution_kind = 'fork_resolution_event', \
                     local_resolution_digest = $3, local_normalized_at = $4 \
                 WHERE realm_id = $1 AND evidence_scope_key = $2 \
                   AND local_resolution_digest IS NULL",
            )
            .bind::<Text, _>(&resolution.realm_id)
            .bind::<Text, _>(&resolution.cell_subject_key)
            .bind::<Text, _>(&resolution.resolution_event_digest)
            .bind::<BigInt, _>(resolution.normalized_at)
            .execute(conn)
            .await?;
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn local_normalization(
        &self,
        realm_id: &str,
        cell_subject_key: &str,
    ) -> PersistenceResult<Option<FederationFrontierResolutionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT realm_id, cell_subject_key, subject, verdict, conflict_evidence_digest,              resolution_event_digest, normalized_at FROM federation_frontier_resolution              WHERE realm_id = $1 AND cell_subject_key = $2",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(cell_subject_key)
        .get_result::<FederationFrontierResolutionRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)
        .map(|row| row.map(Into::into))
    }

    async fn resolve_confirmed_evidence_for_peer(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
        evidence_scope_key: &str,
        resolution_kind: &str,
        resolution_digest: &str,
        resolved_at: i64,
    ) -> PersistenceResult<bool> {
        if resolution_kind != "fork_resolution_event" {
            return Err(PersistenceError::SchemaViolation(
                "frontier evidence resolution kind is not registered".to_owned(),
            ));
        }
        Hash::new(resolution_digest.to_owned()).map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "local resolution digest is invalid: {error}"
            ))
        })?;
        self.record_peer_alignment(
            realm_id,
            peer_id,
            evidence_scope_key,
            resolution_digest,
            resolved_at,
        )
        .await
    }

    async fn record_peer_alignment(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
        evidence_scope_key: &str,
        alignment_digest: &str,
        aligned_at: i64,
    ) -> PersistenceResult<bool> {
        Hash::new(alignment_digest.to_owned()).map_err(|error| {
            PersistenceError::SchemaViolation(format!(
                "peer alignment evidence digest is invalid: {error}"
            ))
        })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let updated = sql_query(
            "UPDATE federation_frontier_confirmed_evidence \
             SET peer_alignment_digest = $4, peer_aligned_at = $5 \
             WHERE realm_id = $1 AND peer_id = $2 AND evidence_scope_key = $3 \
               AND local_resolution_digest IS NOT NULL \
               AND peer_alignment_digest IS NULL",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(peer_id.as_str())
        .bind::<Text, _>(evidence_scope_key)
        .bind::<Text, _>(alignment_digest)
        .bind::<BigInt, _>(aligned_at)
        .execute(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        if updated == 0 {
            return Ok(false);
        }
        sql_query(
            "UPDATE federation_frontier_exchange exchange \
             SET status = CASE WHEN consecutive_failures >= $3 THEN 'peer_stale' ELSE 'healthy' END, \
                 last_error = NULL, updated_at = $4 \
             WHERE realm_id = $1 AND peer_id = $2 \
               AND last_error IN ('witness_disagreement', 'fork_quarantine') \
               AND NOT EXISTS (SELECT 1 FROM federation_frontier_confirmed_evidence evidence \
                   WHERE evidence.realm_id = exchange.realm_id \
                     AND evidence.peer_id = exchange.peer_id \
                     AND evidence.peer_alignment_digest IS NULL)",
        )
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(peer_id.as_str())
        .bind::<Integer, _>(coland_storage::FEDERATION_FRONTIER_STALE_FAILURES)
        .bind::<BigInt, _>(aligned_at)
        .execute(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(true)
    }
}
impl PgFederationFrontierExchangeStore {
    async fn transition(
        &self,
        realm_id: &str,
        peer_id: &DidCoreId,
        observed_at: i64,
        root: Option<&str>,
        reason: Option<&str>,
    ) -> PersistenceResult<FederationFrontierExchangeRecord> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let realm_id = realm_id.to_owned();
        let peer_id = peer_id.clone();
        let root = root.map(ToOwned::to_owned);
        let reason = reason.map(ToOwned::to_owned);
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::realm_identity::ensure_realm_pk(conn, &realm_id).await?;
            // Serialize read/classify/write, including the first absent row.
            // Otherwise a concurrent success can erase confirmed evidence.
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(format!("frontier:{realm_id}:{}", peer_id.as_str()))
                .execute(conn).await?;
            let existing = sql_query("SELECT realm_id, peer_id, status, consecutive_failures, last_success_at, last_failure_at, last_frontier_root, last_error, updated_at FROM federation_frontier_exchange WHERE realm_id = $1 AND peer_id = $2")
                .bind::<Text, _>(&realm_id).bind::<Text, _>(peer_id.as_str())
                .get_result::<FederationFrontierExchangeRow>(conn).await.optional()?
                .map(FederationFrontierExchangeRecord::try_from).transpose()?;
            let record = match reason {
                Some(reason) => frontier_exchange_failure_record(existing, &realm_id, &peer_id, &reason, observed_at),
                None => frontier_exchange_success_record(existing, &realm_id, &peer_id, root.as_deref().expect("success requires observed root"), observed_at),
            };
            Self::put_record(conn, &record).await?;
            Ok(record)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn put_record(
        conn: &mut AsyncPgConnection,
        record: &FederationFrontierExchangeRecord,
    ) -> PersistenceResult<()> {
        sql_query(
            "INSERT INTO federation_frontier_exchange \
             (realm_id, peer_id, status, consecutive_failures, last_success_at, \
              last_failure_at, last_frontier_root, last_error, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (realm_id, peer_id) DO UPDATE SET \
             status = EXCLUDED.status, \
             consecutive_failures = EXCLUDED.consecutive_failures, \
             last_success_at = EXCLUDED.last_success_at, \
             last_failure_at = EXCLUDED.last_failure_at, \
             last_frontier_root = EXCLUDED.last_frontier_root, \
             last_error = EXCLUDED.last_error, \
             updated_at = EXCLUDED.updated_at",
        )
        .bind::<Text, _>(&record.realm_id)
        .bind::<Text, _>(record.peer_id.as_str())
        .bind::<Text, _>(&record.status)
        .bind::<Integer, _>(record.consecutive_failures)
        .bind::<Nullable<BigInt>, _>(record.last_success_at)
        .bind::<Nullable<BigInt>, _>(record.last_failure_at)
        .bind::<Nullable<Text>, _>(record.last_frontier_root.as_deref())
        .bind::<Nullable<Text>, _>(record.last_error.as_deref())
        .bind::<BigInt, _>(record.updated_at)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
    }
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
struct FederationFrontierExchangeRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    peer_id: DidCoreId,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Integer)]
    consecutive_failures: i32,
    #[diesel(sql_type = Nullable<BigInt>)]
    last_success_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    last_failure_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    last_frontier_root: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    last_error: Option<String>,
    #[diesel(sql_type = BigInt)]
    updated_at: i64,
}

#[derive(QueryableByName)]
struct FederationFrontierConfirmedEvidenceRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    peer_id: DidCoreId,
    #[diesel(sql_type = Text)]
    evidence_scope_key: String,
    #[diesel(sql_type = Text)]
    reason: String,
    #[diesel(sql_type = Jsonb)]
    evidence_scope: Value,
    #[diesel(sql_type = BigInt)]
    observed_at: i64,
    #[diesel(sql_type = Nullable<Text>)]
    local_resolution_kind: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    local_resolution_digest: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    local_normalized_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    peer_alignment_digest: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    peer_aligned_at: Option<i64>,
}

#[derive(QueryableByName)]
struct FederationFrontierResolutionRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    cell_subject_key: String,
    #[diesel(sql_type = Jsonb)]
    subject: Value,
    #[diesel(sql_type = Jsonb)]
    verdict: Value,
    #[diesel(sql_type = Text)]
    conflict_evidence_digest: String,
    #[diesel(sql_type = Text)]
    resolution_event_digest: String,
    #[diesel(sql_type = BigInt)]
    normalized_at: i64,
}

impl From<FederationFrontierResolutionRow> for FederationFrontierResolutionRecord {
    fn from(row: FederationFrontierResolutionRow) -> Self {
        Self {
            realm_id: row.realm_id,
            cell_subject_key: row.cell_subject_key,
            subject: row.subject,
            verdict: row.verdict,
            conflict_evidence_digest: row.conflict_evidence_digest,
            resolution_event_digest: row.resolution_event_digest,
            normalized_at: row.normalized_at,
        }
    }
}

impl From<FederationFrontierConfirmedEvidenceRow> for FederationFrontierConfirmedEvidenceRecord {
    fn from(row: FederationFrontierConfirmedEvidenceRow) -> Self {
        Self {
            realm_id: row.realm_id,
            peer_id: row.peer_id,
            evidence_scope_key: row.evidence_scope_key,
            reason: row.reason,
            evidence_scope: row.evidence_scope,
            observed_at: row.observed_at,
            local_resolution_kind: row.local_resolution_kind,
            local_resolution_digest: row.local_resolution_digest,
            local_normalized_at: row.local_normalized_at,
            peer_alignment_digest: row.peer_alignment_digest,
            peer_aligned_at: row.peer_aligned_at,
        }
    }
}

#[derive(QueryableByName)]
struct FederationFrontierReductionCheckpointRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    peer_id: DidCoreId,
    #[diesel(sql_type = Text)]
    remote_snapshot_digest: String,
    #[diesel(sql_type = Text)]
    actor_set_digest: String,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    cursor: Option<String>,
    #[diesel(sql_type = BigInt)]
    updated_at: i64,
}

impl TryFrom<FederationFrontierReductionCheckpointRow> for FederationFrontierReductionCheckpoint {
    type Error = PersistenceError;

    fn try_from(row: FederationFrontierReductionCheckpointRow) -> Result<Self, Self::Error> {
        Ok(Self {
            realm_id: row.realm_id,
            peer_id: row.peer_id,
            remote_snapshot_digest: row.remote_snapshot_digest,
            actor_set_digest: row.actor_set_digest,
            actor_id: serde_json::from_str::<ActorId>(&row.actor_id)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
            cursor: row.cursor,
            updated_at: row.updated_at,
        })
    }
}

impl TryFrom<FederationFrontierExchangeRow> for FederationFrontierExchangeRecord {
    type Error = PersistenceError;

    fn try_from(row: FederationFrontierExchangeRow) -> Result<Self, Self::Error> {
        Ok(Self {
            realm_id: row.realm_id,
            peer_id: row.peer_id,
            status: row.status,
            consecutive_failures: row.consecutive_failures,
            last_success_at: row.last_success_at,
            last_failure_at: row.last_failure_at,
            last_frontier_root: row.last_frontier_root,
            last_error: row.last_error,
            updated_at: row.updated_at,
        })
    }
}
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
