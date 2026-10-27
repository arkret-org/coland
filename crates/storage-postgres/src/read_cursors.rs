//! `ak.private.read_cursor.v1`: the account-private causal-first read cursor
//! winner (actor-private-effects.md §3.4, read-receipts.md §6.5).
//!
//! One transaction serializes a `(AccountId, realm_id, read_scope)` key,
//! answers an exact retry from the ledger, rechecks the producer guard,
//! classifies the candidate position against the current winner and writes
//! the winner and the ledger outcome together. Positions are committed Events
//! of the Realm this Station governs; two positions on one commit stream are
//! ordered by `stream_position`, positions on different streams are causally
//! incomparable. A position whose visibility to the owner this Station cannot
//! prove stays provisional: it is refused and the durable winner is kept.

use arkret_models_collaboration::objects::read_receipts::{
    ReadCursor, ReadCursorCausalRelation, ReadMarkerResponseBody, merge_read_cursors,
};
use arkret_wire::{AccountId, ActorId, CommitStreamRef, RealmId};
use coland_storage::{
    ReadCursorAdvance, ReadCursorAdvanceOutcome, ReadCursorAdvanceRefusal, ReadCursorStore,
};

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Binary, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz,
    async_trait, ids, pg_conn, sql_query,
};

#[derive(Clone)]
pub struct PgReadCursorStore {
    pub(crate) pool: PgPool,
}

impl PgReadCursorStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(QueryableByName)]
struct LedgerRow {
    #[diesel(sql_type = Binary)]
    canonical_event_digest: Vec<u8>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    outcome: Option<serde_json::Value>,
}

#[derive(QueryableByName)]
struct TenureRow {
    #[diesel(sql_type = Text)]
    service_id: String,
}

#[derive(QueryableByName)]
struct JoinFloorRow {
    #[diesel(sql_type = BigInt, column_name = current_stream_position)]
    _position: i64,
}

#[derive(QueryableByName)]
struct PositionRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    stream_key: String,
    #[diesel(sql_type = Jsonb)]
    stream_ref: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
}

#[derive(QueryableByName)]
struct WinnerRow {
    #[diesel(sql_type = Jsonb)]
    cursor: serde_json::Value,
    #[diesel(sql_type = Timestamptz)]
    derived_updated_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Text)]
    position_stream_key: String,
    #[diesel(sql_type = BigInt)]
    position_stream_position: i64,
}

fn scope_key(cursor: &ReadCursor) -> PersistenceResult<String> {
    String::from_utf8(
        arkret_canonical::canonical_json_bytes(&cursor.read_scope)
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
    )
    .map_err(|error| PersistenceError::Internal(error.to_string()))
}

fn marker(
    cursor: &ReadCursor,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> ReadMarkerResponseBody {
    ReadMarkerResponseBody {
        realm_id: cursor.realm_id.clone(),
        actor_id: cursor.actor_id.clone(),
        device_id: cursor.device_id.clone(),
        read_scope: cursor.read_scope.clone(),
        position: cursor.position.clone(),
        updated_at,
    }
}

fn decode<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
    what: &str,
) -> PersistenceResult<T> {
    serde_json::from_value(value)
        .map_err(|error| PersistenceError::Internal(format!("stored {what} is invalid: {error}")))
}

/// The candidate's commit coordinate once its visibility is proved.
struct ProvedPosition {
    stream_key: String,
    stream_position: i64,
}

/// Prove that `advance.cursor.position` names a committed Event of the Realm
/// that the owner can see, at this transaction's cut.
async fn prove_position(
    conn: &mut AsyncPgConnection,
    advance: &ReadCursorAdvance,
) -> Result<Result<ProvedPosition, ReadCursorAdvanceRefusal>, PgTransactionError> {
    let realm_id = advance.cursor.realm_id.as_str();
    let tenure = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1 FOR SHARE")
        .bind::<Text, _>(realm_id)
        .get_result::<TenureRow>(&mut *conn)
        .await
        .optional()?;
    if tenure.is_none_or(|row| row.service_id != advance.station_id.as_str()) {
        return Ok(Err(ReadCursorAdvanceRefusal::Unproved(
            "this Station does not govern the Realm's committed history",
        )));
    }
    let owner = ActorId::account(advance.owner.clone()).to_string();
    let Some(_membership) = sql_query(
        "SELECT current_stream_position FROM member_state_current_states \
         WHERE realm_id=$1 AND member_id=$2 AND membership='join' FOR SHARE",
    )
    .bind::<Text, _>(realm_id)
    .bind::<Text, _>(&owner)
    .get_result::<JoinFloorRow>(&mut *conn)
    .await
    .optional()?
    else {
        return Ok(Err(ReadCursorAdvanceRefusal::NotMember));
    };
    let token =
        ids::parse_event_id(advance.cursor.position.event_id.as_str()).ok_or_else(|| {
            PersistenceError::SchemaViolation("read cursor position Event id is invalid".to_owned())
        })?;
    let Some(position) = sql_query(
        "SELECT c.realm_id, c.stream_key, c.stream_ref, c.stream_position FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.state='committed'",
    )
    .bind::<Binary, _>(token.to_vec())
    .get_result::<PositionRow>(&mut *conn)
    .await
    .optional()?
    else {
        return Ok(Err(ReadCursorAdvanceRefusal::PositionNotInRealm));
    };
    if position.realm_id != realm_id {
        return Ok(Err(ReadCursorAdvanceRefusal::PositionNotInRealm));
    }
    let stream: CommitStreamRef = decode(position.stream_ref, "read cursor position stream")?;
    if stream.realm_id() != &advance.cursor.realm_id
        || crate::authority_commit::stream_key(&stream)? != position.stream_key
    {
        return Err(PersistenceError::SchemaViolation(
            "read cursor position stream does not bind its accepted coordinate".into(),
        )
        .into());
    }
    let caller = ActorId::account(advance.owner.clone());
    let floor = match &stream {
        CommitStreamRef::Realm { realm_id } => {
            sql_query("SELECT 1 FROM realm_bootstrap_current_states WHERE realm_id=$1 AND state_family='realm_history_access' FOR SHARE")
                .bind::<Text, _>(realm_id.as_str()).execute(&mut *conn).await?;
            crate::account_stream_scan::caller_realm_floor_in_connection(conn, realm_id, &caller)
                .await?
        }
        CommitStreamRef::Circle {
            realm_id,
            circle_id,
        } => {
            // Pin the exact accepted Circle current and join while evaluating
            // the same parent-bound interval used by ordinary stream reads.
            sql_query(
                "SELECT 1 FROM circle_current_states WHERE realm_id=$1 AND circle_id=$2 FOR SHARE",
            )
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(circle_id.as_str())
            .execute(&mut *conn)
            .await?;
            sql_query("SELECT 1 FROM circle_member_state_current_states WHERE realm_id=$1 AND circle_id=$2 AND member_id=$3 FOR SHARE")
                .bind::<Text, _>(realm_id.as_str()).bind::<Text, _>(circle_id.as_str())
                .bind::<Text, _>(&owner).execute(&mut *conn).await?;
            crate::account_stream_scan::caller_circle_floor_in_connection(
                conn, realm_id, circle_id, &caller,
            )
            .await?
        }
        _ => {
            return Ok(Err(ReadCursorAdvanceRefusal::Unproved(
                "the position stream visibility is not proved at this cut",
            )));
        }
    };
    let Some(floor) = floor else {
        return Ok(Err(ReadCursorAdvanceRefusal::PositionNotReadable));
    };
    if position.stream_position
        < i64::try_from(floor.oldest_position).map_err(PersistenceError::database)?
    {
        return Ok(Err(ReadCursorAdvanceRefusal::PositionNotReadable));
    }
    Ok(Ok(ProvedPosition {
        stream_key: position.stream_key,
        stream_position: position.stream_position,
    }))
}

async fn advance_in_connection(
    conn: &mut AsyncPgConnection,
    advance: &ReadCursorAdvance,
) -> Result<ReadCursorAdvanceOutcome, PgTransactionError> {
    let account_key = advance.owner.to_string();
    let realm_id = advance.cursor.realm_id.as_str();
    let read_scope_key = scope_key(&advance.cursor)?;
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(format!(
            "read-cursor:{account_key}:{realm_id}:{read_scope_key}"
        ))
        .execute(&mut *conn)
        .await?;
    if let Some(row) = sql_query(
        "SELECT canonical_event_digest, outcome FROM actor_private_events \
         WHERE event_id=$1 AND kind='ak.read_cursor.advance'",
    )
    .bind::<Text, _>(advance.event.event_id.as_str())
    .get_result::<LedgerRow>(&mut *conn)
    .await
    .optional()?
    {
        crate::account_private_erasure::require_private_write_in_connection(conn, &advance.owner)
            .await?;
        if row.canonical_event_digest != advance.canonical_event_digest {
            return Ok(ReadCursorAdvanceOutcome::Refused(
                ReadCursorAdvanceRefusal::DuplicateConflict,
            ));
        }
        return Ok(ReadCursorAdvanceOutcome::Replayed(decode(
            row.outcome.ok_or_else(|| {
                PersistenceError::Internal("read cursor advance has no outcome".to_owned())
            })?,
            "read cursor advance outcome",
        )?));
    }
    if let Some(guard) = &advance.producer_guard {
        crate::authority_commit::check_self_producer_guard_in_connection(
            conn,
            &advance.event,
            guard,
            advance.accepted_at,
        )
        .await?;
    }
    let candidate = match prove_position(conn, advance).await? {
        Ok(position) => position,
        Err(refusal) => return Ok(ReadCursorAdvanceOutcome::Refused(refusal)),
    };
    crate::account_private_erasure::require_private_write_in_connection(conn, &advance.owner)
        .await?;
    let current = sql_query(
        "SELECT cursor, derived_updated_at, position_stream_key, position_stream_position \
         FROM read_cursor_winners WHERE account_key=$1 AND realm_id=$2 AND read_scope_key=$3 \
         FOR UPDATE",
    )
    .bind::<Text, _>(&account_key)
    .bind::<Text, _>(realm_id)
    .bind::<Text, _>(&read_scope_key)
    .get_result::<WinnerRow>(&mut *conn)
    .await
    .optional()?;
    let (outcome, candidate_won) = match current {
        None => (marker(&advance.cursor, advance.event.created_at), true),
        Some(row) => {
            let current_cursor: ReadCursor = decode(row.cursor, "read cursor winner")?;
            let relation = if row.position_stream_key != candidate.stream_key {
                ReadCursorCausalRelation::Concurrent
            } else {
                match candidate.stream_position.cmp(&row.position_stream_position) {
                    std::cmp::Ordering::Greater => {
                        ReadCursorCausalRelation::CandidateDominatesCurrent
                    }
                    std::cmp::Ordering::Less => ReadCursorCausalRelation::CurrentDominatesCandidate,
                    std::cmp::Ordering::Equal => ReadCursorCausalRelation::Concurrent,
                }
            };
            let merged = merge_read_cursors(&current_cursor, &advance.cursor, relation)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            if merged.provisional {
                return Ok(ReadCursorAdvanceOutcome::Refused(
                    ReadCursorAdvanceRefusal::Unproved(
                        "the causal relation to the current winner is undecidable",
                    ),
                ));
            }
            if std::ptr::eq(merged.winner, &advance.cursor) {
                (marker(&advance.cursor, advance.event.created_at), true)
            } else {
                (marker(&current_cursor, row.derived_updated_at), false)
            }
        }
    };
    if candidate_won {
        sql_query(
            "INSERT INTO read_cursor_winners \
             (account_key, realm_id, read_scope_key, cursor, winning_event_id, \
              derived_updated_at, position_stream_key, position_stream_position) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) \
             ON CONFLICT (account_key, realm_id, read_scope_key) DO UPDATE SET \
             cursor=EXCLUDED.cursor, winning_event_id=EXCLUDED.winning_event_id, \
             derived_updated_at=EXCLUDED.derived_updated_at, \
             position_stream_key=EXCLUDED.position_stream_key, \
             position_stream_position=EXCLUDED.position_stream_position",
        )
        .bind::<Text, _>(&account_key)
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(&read_scope_key)
        .bind::<Jsonb, _>(
            serde_json::to_value(&advance.cursor)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        )
        .bind::<Text, _>(advance.event.event_id.as_str())
        .bind::<Timestamptz, _>(advance.event.created_at)
        .bind::<Text, _>(&candidate.stream_key)
        .bind::<BigInt, _>(candidate.stream_position)
        .execute(&mut *conn)
        .await?;
    }
    sql_query(
        "INSERT INTO actor_private_events \
         (id, event_id, actor_id, owner_account_id, kind, canonical_event_digest, envelope, outcome, accepted_at) \
         VALUES ($1,$2,$3,$4,'ak.read_cursor.advance',$5,$6,$7,$8)",
    )
    .bind::<Binary, _>(advance.event.event_id.token_bytes().to_vec())
    .bind::<Text, _>(advance.event.event_id.as_str())
    .bind::<Text, _>(advance.event.actor_id.to_string())
    .bind::<Jsonb, _>(
        serde_json::to_value(&advance.owner)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Binary, _>(&advance.canonical_event_digest)
    .bind::<Jsonb, _>(
        serde_json::to_value(&advance.event)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Jsonb, _>(
        serde_json::to_value(&outcome)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    )
    .bind::<Timestamptz, _>(advance.accepted_at)
    .execute(&mut *conn)
    .await?;
    Ok(ReadCursorAdvanceOutcome::Accepted {
        marker: outcome,
        candidate_won,
    })
}

#[async_trait]
impl ReadCursorStore for PgReadCursorStore {
    async fn advance(
        &self,
        advance: &ReadCursorAdvance,
    ) -> PersistenceResult<ReadCursorAdvanceOutcome> {
        if advance.cursor.actor_id != ActorId::account(advance.owner.clone())
            || advance.event.actor_id != advance.cursor.actor_id
            || advance.event.realm_id != advance.cursor.realm_id
            || advance.event.kind != arkret_wire::EventKind::ReadCursorAdvance
        {
            return Err(PersistenceError::SchemaViolation(
                "read cursor advance owner, actor, Realm or kind is not bound".to_owned(),
            ));
        }
        if advance.canonical_event_digest.len() != 32 {
            return Err(PersistenceError::SchemaViolation(
                "read cursor advance digest must be 32 bytes".to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            advance_in_connection(conn, advance).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn list(
        &self,
        owner: &AccountId,
        realm_id: Option<&RealmId>,
    ) -> PersistenceResult<Vec<ReadMarkerResponseBody>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT cursor, derived_updated_at, position_stream_key, position_stream_position \
             FROM read_cursor_winners WHERE account_key=$1 AND ($2 = '' OR realm_id=$2) \
             ORDER BY realm_id, read_scope_key",
        )
        .bind::<Text, _>(owner.to_string())
        .bind::<Text, _>(realm_id.map_or("", RealmId::as_str))
        .load::<WinnerRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                let cursor: ReadCursor = decode(row.cursor, "read cursor winner")?;
                Ok(marker(&cursor, row.derived_updated_at))
            })
            .collect()
    }
}
