use coland_storage::{
    AcceptedDeviceAuthorizationOutcome, AuthorityCommitStore, AuthorityCommitTransaction,
    AuthorityCommitWriteOutcome, CurrentRealmAuthority, ForwardAttemptRecord, ForwardAttemptStatus,
    OrdinaryRealmBootstrapCommitOutcome, OrdinaryRealmBootstrapCommitUnit, PcrGenesisCommitOutcome,
    PcrGenesisCommitUnit, QueuedEventRecord, QueuedEventStatus, SelfProducerCommitGuard,
};
use diesel::sql_types::{Bool, SmallInt};
use serde::de::DeserializeOwned;

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Binary, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl,
    Text, Timestamptz, Value, async_trait, ids, pg_conn, sql_query,
};
use crate::agent_current_results::lock_agent_producer_current;
use crate::capability_grant_current_results::{
    commit_capability_grant_current_result_in_connection,
    commit_realm_authority_root_current_result_in_connection,
};

pub(crate) mod replica;

#[derive(Clone)]
pub struct PgAuthorityCommitStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct AuthorityRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = BigInt)]
    generation: i64,
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = Jsonb)]
    authority_ref: Value,
    #[diesel(sql_type = Nullable<Text>)]
    last_handoff_ref: Option<String>,
}

#[derive(QueryableByName)]
struct RealmGenerationRow {
    #[diesel(sql_type = BigInt)]
    generation: i64,
}

#[derive(QueryableByName)]
struct EventRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Text>)]
    rejection_reason: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    commit_json: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    forward_status: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    forward_original_submission: Option<Value>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    forward_accepted_commit: Option<Value>,
    #[diesel(sql_type = Nullable<Text>)]
    forward_reason_code: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    forward_attempted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(QueryableByName)]
struct EventPkRow {
    #[diesel(sql_type = BigInt)]
    event_pk: i64,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Binary)]
    canonical_bytes: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

#[derive(QueryableByName)]
struct CommitRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

#[derive(QueryableByName)]
struct OrdinaryBootstrapUnitRow {
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Binary)]
    exact_request_body: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    commits_json: Value,
}

#[derive(QueryableByName)]
struct PcrGenesisUnitRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Binary)]
    exact_request_body: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    result_json: Value,
}

#[derive(QueryableByName)]
struct HeadRow {
    #[diesel(sql_type = Jsonb)]
    stream_ref: Value,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
    #[diesel(sql_type = Text)]
    commit_id: String,
}

#[derive(QueryableByName)]
struct SnapshotCurrentRow {
    #[diesel(sql_type = Text)]
    selector_kind: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    selector_subject: Option<Value>,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    source_stream_ref: Option<Value>,
}

#[derive(QueryableByName)]
struct MimiRoomBindingCurrentRow {
    #[diesel(sql_type = Text)]
    mimi_room_uri: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Text)]
    current_event_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn decode_mimi_room_binding_current(
    row: MimiRoomBindingCurrentRow,
) -> PersistenceResult<coland_storage::MimiRoomBindingCurrentRecord> {
    let selector = arkret_wire::CurrentSelector::MimiRoomBinding {
        mimi_room_uri: arkret_wire::MimiRoomUri::new(row.mimi_room_uri)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    };
    let current = arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingCurrentRow {
        selector,
        revision: arkret_wire::CurrentRevision {
            commit_id: decode_text(row.current_commit_id, "MIMI current RealmCommit id")?,
            stream_position: to_u64(row.current_stream_position, "MIMI current stream position")?,
        },
        value: decode_json(row.value, "MIMI current binding payload")?,
    };
    current
        .validate()
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    Ok(coland_storage::MimiRoomBindingCurrentRecord {
        current,
        source_event_id: decode_text(row.current_event_id, "MIMI current source Event id")?,
        realm_id: decode_text(row.realm_id, "MIMI current Realm id")?,
    })
}

fn invalid_mimi_migration() -> PersistenceError {
    PersistenceError::Conflict(
        coland_storage::ConflictCode::MimiRoomBindingMigrationProofInvalid.to_string(),
    )
}

fn mimi_migration_topology_matches(left: &Value, right: &Value) -> bool {
    [
        "hub_provider_id",
        "follower_provider_ids",
        "local_provider_role",
        "mls_group_id",
    ]
    .iter()
    .all(|field| left.get(*field) == right.get(*field))
}

async fn verify_mimi_migration_in_connection(
    conn: &mut AsyncPgConnection,
    payload: &arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingPayload,
    value: &Value,
    previous: &MimiRoomBindingCurrentRow,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingMigrationOutcome;

    let proof = payload
        .migration_proof
        .as_ref()
        .ok_or_else(invalid_mimi_migration)?;
    let outcome = payload
        .migration_outcome
        .ok_or_else(invalid_mimi_migration)?;
    if previous.current_event_id != proof.migrating_event_id.as_str()
        || previous.current_commit_id != proof.migrating_commit_id.as_str()
        || previous.realm_id != payload.binding_scope.realm_id.as_str()
    {
        return Err(invalid_mimi_migration());
    }
    let migrating_row = sql_query(
        "SELECT c.commit_json, e.envelope FROM realm_commits c \
         JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(proof.migrating_commit_id.as_str())
    .get_result::<CommitStreamRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(invalid_mimi_migration)?;
    let migrating_commit: arkret_wire::RealmCommit =
        decode_json(migrating_row.commit_json, "MIMI migrating RealmCommit")?;
    let migrating_event: arkret_wire::Event =
        decode_json(migrating_row.envelope, "MIMI migrating Event")?;
    if migrating_commit.commit_id != proof.migrating_commit_id
        || migrating_commit.event_ref != proof.migrating_event_id
        || migrating_event.event_id != proof.migrating_event_id
        || migrating_event.kind != arkret_wire::EventKind::MimiRoomBinding
        || migrating_commit.realm_id != payload.binding_scope.realm_id
        || migrating_event.realm_id != payload.binding_scope.realm_id
        || migrating_commit.stream_position
            != u64::try_from(previous.current_stream_position)
                .map_err(|_| invalid_mimi_migration())?
    {
        return Err(invalid_mimi_migration());
    }
    let migrating_value =
        serde_json::to_value(&migrating_event.payload).map_err(PersistenceError::database)?;
    if migrating_value != previous.value
        || migrating_value.get("status").and_then(Value::as_str) != Some("migrating")
    {
        return Err(invalid_mimi_migration());
    }
    let prior_row = sql_query(
        "SELECT c.commit_json, e.envelope FROM realm_commits c \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND c.stream_ref=$2 AND c.stream_position<$3 \
           AND e.envelope->>'kind'='ak.mimi.room_binding' \
           AND e.envelope->'payload'->>'mimi_room_uri'=$4 \
         ORDER BY c.stream_position DESC LIMIT 1 FOR UPDATE",
    )
    .bind::<Text, _>(payload.binding_scope.realm_id.as_str())
    .bind::<Jsonb, _>(
        serde_json::to_value(&migrating_commit.stream_ref).map_err(PersistenceError::database)?,
    )
    .bind::<BigInt, _>(previous.current_stream_position)
    .bind::<Text, _>(payload.mimi_room_uri.as_str())
    .get_result::<CommitStreamRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(invalid_mimi_migration)?;
    let prior_commit: arkret_wire::RealmCommit =
        decode_json(prior_row.commit_json, "MIMI previous accepted RealmCommit")?;
    let prior_event: arkret_wire::Event =
        decode_json(prior_row.envelope, "MIMI previous accepted Event")?;
    if prior_commit.commit_id != proof.previous_accepted_commit_id
        || prior_commit.event_ref != proof.previous_accepted_event_id
        || prior_event.event_id != proof.previous_accepted_event_id
        || prior_event.kind != arkret_wire::EventKind::MimiRoomBinding
        || prior_commit.realm_id != payload.binding_scope.realm_id
        || prior_event.realm_id != payload.binding_scope.realm_id
        || prior_commit.stream_ref != migrating_commit.stream_ref
    {
        return Err(invalid_mimi_migration());
    }
    let prior_value =
        serde_json::to_value(&prior_event.payload).map_err(PersistenceError::database)?;
    if prior_value.get("status").and_then(Value::as_str) != Some("accepted") {
        return Err(invalid_mimi_migration());
    }
    for state in [&prior_value, &migrating_value] {
        for field in ["profile", "mimi_room_uri", "binding_scope"] {
            if state.get(field) != value.get(field) {
                return Err(invalid_mimi_migration());
            }
        }
    }
    let expected_topology = match outcome {
        MimiRoomBindingMigrationOutcome::Completed => &migrating_value,
        MimiRoomBindingMigrationOutcome::RolledBack => &prior_value,
    };
    if !mimi_migration_topology_matches(value, expected_topology) {
        return Err(invalid_mimi_migration());
    }
    if let Some(group_id) = payload.mls_group_id.as_ref() {
        let scope = arkret_wire::ScopeRef::Realm {
            realm_id: payload.binding_scope.realm_id.clone(),
        };
        let key = crate::mls_group_current_results::scope_key(&scope)?;
        let current = crate::mls_group_current_results::locked_group(conn, &key)
            .await?
            .ok_or_else(invalid_mimi_migration)?;
        let derived = scope
            .canonical_mls_group_id()
            .map_err(|_| invalid_mimi_migration())?;
        if current.value.effective_scope != scope || group_id.as_str() != derived.as_str() {
            return Err(invalid_mimi_migration());
        }
        // This tracker was installed only after RFC 9420 GroupInfo/tree or
        // Commit verification. Lock that accepted state in this transaction.
        let tracker = arkret_mls::MlsPublicGroupTracker::restore(
            &current.public_state,
            derived.as_str(),
            current.value.epoch,
        )
        .map_err(|_| invalid_mimi_migration())?;
        let binding = tracker
            .governance_binding()
            .map_err(|_| invalid_mimi_migration())?;
        if tracker.group_id() != derived.as_str()
            || binding.effective_scope() != &scope
            || binding.next_epoch() != current.value.epoch
        {
            return Err(invalid_mimi_migration());
        }
    }
    Ok(())
}

pub(crate) async fn commit_mimi_room_binding_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::MimiRoomBinding {
        return Ok(());
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
        conn,
        event,
        commit.committed_at,
    )
    .await?;
    let value = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let payload: arkret_models_collaboration::events_payloads::mimi::MimiRoomBindingPayload =
        decode_json(value.clone(), "MIMI room binding Event payload")?;
    payload.validate_shape().map_err(invalid)?;
    if payload.binding_scope.realm_id != event.realm_id {
        return Err(PersistenceError::SchemaViolation(
            "MIMI room binding Realm does not match its Event".to_owned(),
        ));
    }
    let room_uri = payload.mimi_room_uri.as_str();
    let previous = sql_query(
        "SELECT mimi_room_uri,realm_id,current_commit_id,current_stream_position,current_event_id,value \
         FROM mimi_room_binding_current_results WHERE mimi_room_uri=$1 FOR UPDATE",
    )
    .bind::<Text, _>(room_uri)
    .get_result::<MimiRoomBindingCurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let previous_status = previous
        .as_ref()
        .and_then(|row| row.value.get("status"))
        .and_then(Value::as_str);
    let next_status = value.get("status").and_then(Value::as_str);
    let allowed = matches!(
        (previous_status, next_status),
        (None, Some("proposed" | "accepted"))
            | (Some("proposed"), Some("accepted" | "revoked"))
            | (Some("accepted"), Some("migrating" | "revoked"))
            | (Some("migrating"), Some("accepted"))
            | (Some("migrating"), Some("revoked"))
    );
    if !allowed {
        return Err(PersistenceError::SchemaViolation(
            "mimi_room_binding_status_transition_invalid".to_owned(),
        ));
    }
    if previous_status == Some("migrating") && next_status == Some("accepted") {
        verify_mimi_migration_in_connection(
            conn,
            &payload,
            &value,
            previous.as_ref().ok_or_else(invalid_mimi_migration)?,
        )
        .await?;
    } else if payload.migration_outcome.is_some() || payload.migration_proof.is_some() {
        return Err(invalid_mimi_migration());
    }
    let stream_position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("MIMI current stream position exceeds i64".to_owned())
    })?;
    sql_query(
        "INSERT INTO mimi_room_binding_current_results \
         (mimi_room_uri,realm_id,current_commit_id,current_stream_position,current_event_id,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) \
         ON CONFLICT (mimi_room_uri) DO UPDATE SET \
           realm_id=EXCLUDED.realm_id,current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           current_event_id=EXCLUDED.current_event_id,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(room_uri)
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(stream_position)
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

/// The head of every commit stream of one Realm, as a loose index scan over
/// `realm_commits_realm_stream_tail_idx`: one index probe per stream, never
/// a walk over the Realm's history or other Realms' streams. The row
/// comparisons keep each probe on the Realm-prefixed index.
pub(crate) const REALM_STREAM_HEADS_SQL: &str = "\
    WITH RECURSIVE stream_keys AS ( \
      (SELECT stream_key FROM realm_commits \
       WHERE (realm_id, stream_key) >= ($1, '') AND realm_id = $1 \
       ORDER BY realm_id, stream_key LIMIT 1) \
      UNION ALL \
      SELECT (SELECT next_row.stream_key FROM realm_commits next_row \
              WHERE (next_row.realm_id, next_row.stream_key) > ($1, stream_keys.stream_key) \
                AND next_row.realm_id = $1 \
              ORDER BY next_row.realm_id, next_row.stream_key LIMIT 1) \
      FROM stream_keys WHERE stream_keys.stream_key IS NOT NULL \
    ) \
    SELECT head.stream_ref, head.stream_position, head.commit_id \
    FROM stream_keys CROSS JOIN LATERAL ( \
      SELECT stream_ref, stream_position, commit_id FROM realm_commits \
      WHERE realm_id = $1 AND stream_key = stream_keys.stream_key \
      ORDER BY stream_position DESC LIMIT 1) head \
    WHERE stream_keys.stream_key IS NOT NULL";

#[derive(QueryableByName)]
struct SnapshotRow {
    #[diesel(sql_type = Jsonb)]
    snapshot_json: Value,
}

#[derive(QueryableByName)]
struct HandoffRow {
    #[diesel(sql_type = Jsonb)]
    handoff_json: Value,
}

#[derive(QueryableByName)]
struct CommitStreamRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

#[derive(QueryableByName)]
struct StreamPageRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    envelope: Option<Value>,
}

#[derive(QueryableByName)]
struct PresenceRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

fn forward_original_conflict(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("duplicate_conflict: {detail}"))
}

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_string())
}

/// The Snapshot ref names its complete canonical identity body, never its
/// signature digest. Cryptographic authority verification remains separate.
pub(crate) fn verify_snapshot_content_id(
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> PersistenceResult<()> {
    let body = arkret_canonical::canonical::unsigned_value(snapshot, &["snapshot_id", "signature"])
        .map_err(invalid)?;
    let expected = arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&body).map_err(invalid)?,
    ));
    if snapshot.snapshot_id != expected {
        return Err(invalid(
            "handoff snapshot canonical content address mismatch",
        ));
    }
    Ok(())
}

fn require_exact_commit_replay(
    existing_commit: &Value,
    candidate_commit: &Value,
) -> PersistenceResult<()> {
    if existing_commit == candidate_commit {
        return Ok(());
    }
    Err(PersistenceError::Conflict(
        "duplicate_conflict: Event already has a different RealmCommit".into(),
    ))
}

/// Recognize a durable replay without bypassing the normal authority writer.
/// The caller holds the Realm authorization lock; only a complete accepted
/// Event and Commit witness can replace a current-state successor check.
pub(crate) async fn is_exact_accepted_event_replay(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<bool> {
    #[derive(QueryableByName)]
    struct AcceptedReplay {
        #[diesel(sql_type = Binary)]
        canonical_bytes: Vec<u8>,
        #[diesel(sql_type = Jsonb)]
        envelope: Value,
        #[diesel(sql_type = Jsonb)]
        commit_json: Value,
    }
    let existing = sql_query(
        "SELECT e.canonical_bytes,e.envelope,c.commit_json FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.state='committed'",
    )
    .bind::<Binary, _>(event.event_id.token_bytes().to_vec())
    .get_result::<AcceptedReplay>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(existing) = existing else {
        return Ok(false);
    };
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().map_err(invalid)?)
            .map_err(PersistenceError::database)?;
    if existing.canonical_bytes != canonical_bytes
        || existing.envelope != serde_json::to_value(event).map_err(PersistenceError::database)?
    {
        return Err(PersistenceError::Conflict("event_hash_collision".into()));
    }
    require_exact_commit_replay(
        &existing.commit_json,
        &serde_json::to_value(commit).map_err(PersistenceError::database)?,
    )?;
    Ok(true)
}

fn decode_json<T: DeserializeOwned>(value: Value, what: &str) -> PersistenceResult<T> {
    serde_json::from_value(value)
        .map_err(|error| PersistenceError::Internal(format!("stored {what} is invalid: {error}")))
}

fn decode_text<T: DeserializeOwned>(value: String, what: &str) -> PersistenceResult<T> {
    decode_json(Value::String(value), what)
}

fn to_i64(value: u64, what: &str) -> PersistenceResult<i64> {
    i64::try_from(value).map_err(|_| invalid(format!("{what} exceeds PostgreSQL bigint")))
}

fn to_u64(value: i64, what: &str) -> PersistenceResult<u64> {
    u64::try_from(value)
        .map_err(|_| PersistenceError::Internal(format!("stored {what} is negative")))
}

pub(crate) fn stream_key(stream_ref: &arkret_wire::CommitStreamRef) -> PersistenceResult<String> {
    String::from_utf8(
        arkret_canonical::canonical_json_bytes(stream_ref).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)
}

/// The oldest retained Commit of one stream.
pub(crate) const STREAM_FLOOR_SQL: &str = "SELECT commit_json FROM realm_commits \
     WHERE stream_key = $1 ORDER BY stream_position ASC LIMIT 1";
/// One keyset page toward newer Commits. A member Station's chain node has
/// no Event and is read as its Commit alone.
pub(crate) const STREAM_PAGE_AFTER_SQL: &str = "SELECT c.commit_json, e.envelope \
     FROM realm_commits c LEFT JOIN canonical_events e ON e.pk = c.event_pk \
     WHERE c.stream_key = $1 AND c.stream_position > $2 \
     ORDER BY c.stream_position ASC LIMIT $3";
/// One keyset page toward older Commits.
pub(crate) const STREAM_PAGE_BEFORE_SQL: &str = "SELECT c.commit_json, e.envelope \
     FROM realm_commits c LEFT JOIN canonical_events e ON e.pk = c.event_pk \
     WHERE c.stream_key = $1 AND c.stream_position < $2 \
     ORDER BY c.stream_position DESC LIMIT $3";
/// The newest page of one stream.
pub(crate) const STREAM_PAGE_NEWEST_SQL: &str = "SELECT c.commit_json, e.envelope \
     FROM realm_commits c LEFT JOIN canonical_events e ON e.pk = c.event_pk \
     WHERE c.stream_key = $1 ORDER BY c.stream_position DESC LIMIT $2";

/// One physical keyset page of a single commit stream on the caller's
/// connection (and therefore its read cut). This is not an authorization
/// decision; public callers go through the Account-scoped scan.
pub(crate) async fn stream_page_in_connection(
    conn: &mut AsyncPgConnection,
    request: &arkret_wire::StreamScanRequest,
) -> PersistenceResult<arkret_wire::StreamScanOutcome> {
    request.validate().map_err(invalid)?;
    let key = stream_key(&request.stream_ref)?;
    let floor = sql_query(STREAM_FLOOR_SQL)
        .bind::<Text, _>(&key)
        .get_result::<CommitRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
    let readable_floor = floor
        .map(|row| {
            let commit: arkret_wire::RealmCommit =
                decode_json(row.commit_json, "first RealmCommit")?;
            if commit.stream_position != 0 {
                return Err(invalid("stored stream has no genesis RealmCommit"));
            }
            Ok(arkret_wire::ReadableFloor {
                oldest_position: 0,
                floor_commit_id: commit.commit_id,
                floor_reason: arkret_wire::ReadableFloorReason::StreamStart,
            })
        })
        .transpose()?;
    stream_page_above_floor_in_connection(conn, request, readable_floor).await
}

/// One keyset page of a single commit stream bounded below by `floor`: no
/// Commit under `floor.oldest_position` is returned, and a page that stops
/// at the floor is not reported as truncated (`service-http-binding.md`
/// §3.1). The floor itself is the caller's decision; `None` means the stream
/// has no Commit yet.
pub(crate) async fn stream_page_above_floor_in_connection(
    conn: &mut AsyncPgConnection,
    request: &arkret_wire::StreamScanRequest,
    readable_floor: Option<arkret_wire::ReadableFloor>,
) -> PersistenceResult<arkret_wire::StreamScanOutcome> {
    request.validate().map_err(invalid)?;
    let key = stream_key(&request.stream_ref)?;
    let limit = i64::from(request.limit) + 1;
    let lowest = readable_floor
        .as_ref()
        .map(|floor| to_i64(floor.oldest_position, "readable floor"))
        .transpose()?
        .unwrap_or(0);
    let rows = match request.direction {
        arkret_wire::StreamScanDirection::After(after) => {
            let after = after
                .map(|position| to_i64(position, "stream cursor"))
                .transpose()?
                .unwrap_or(-1)
                .max(lowest - 1);
            sql_query(STREAM_PAGE_AFTER_SQL)
                .bind::<Text, _>(&key)
                .bind::<BigInt, _>(after)
                .bind::<BigInt, _>(limit)
                .load::<StreamPageRow>(&mut *conn)
                .await
        }
        arkret_wire::StreamScanDirection::Before(Some(before)) => {
            let before = to_i64(before, "stream cursor")?;
            sql_query(STREAM_PAGE_BEFORE_SQL)
                .bind::<Text, _>(&key)
                .bind::<BigInt, _>(before)
                .bind::<BigInt, _>(limit)
                .load::<StreamPageRow>(&mut *conn)
                .await
        }
        arkret_wire::StreamScanDirection::Before(None) => {
            sql_query(STREAM_PAGE_NEWEST_SQL)
                .bind::<Text, _>(&key)
                .bind::<BigInt, _>(limit)
                .load::<StreamPageRow>(&mut *conn)
                .await
        }
    }
    .map_err(PersistenceError::database)?;
    let committed_events = rows
        .into_iter()
        .map(|row| {
            let commit = decode_json(row.commit_json, "RealmCommit")?;
            Ok(match row.envelope {
                Some(envelope) => {
                    arkret_wire::CommittedEventView::Full(arkret_wire::CommittedEventFullView {
                        commit,
                        event: decode_json(envelope, "committed Event")?,
                    })
                }
                None => arkret_wire::CommittedEventView::Withheld(
                    arkret_wire::CommittedEventWithheldView {
                        commit,
                        event_disclosure: arkret_wire::EventDisclosure {
                            status: arkret_wire::EventDisclosureStatus::Withheld,
                        },
                    },
                ),
            })
        })
        .collect::<PersistenceResult<Vec<_>>>()?
        .into_iter()
        .filter(|item| {
            readable_floor
                .as_ref()
                .is_none_or(|floor| item.commit().stream_position >= floor.oldest_position)
        })
        .collect::<Vec<_>>();
    // Rows are ordered away from the cursor, so dropping those under the
    // floor keeps the page contiguous; one row beyond `limit` inside the
    // interval is what makes the page truncated.
    let truncated = committed_events.len() > usize::from(request.limit);
    let committed_events = committed_events
        .into_iter()
        .take(usize::from(request.limit))
        .collect();
    let outcome = arkret_wire::StreamScanOutcome {
        committed_events,
        readable_floor,
        truncated,
    };
    outcome.validate_for_request(request).map_err(invalid)?;
    Ok(outcome)
}

fn authority_from_row(row: AuthorityRow) -> PersistenceResult<CurrentRealmAuthority> {
    Ok(CurrentRealmAuthority {
        realm_id: decode_text(row.realm_id, "authority Realm id")?,
        generation: to_u64(row.generation, "authority generation")?,
        service_id: decode_text(row.service_id, "authority service id")?,
        authority_ref: decode_json(row.authority_ref, "authority reference")?,
        last_handoff_ref: row
            .last_handoff_ref
            .map(|value| decode_text(value, "authority handoff id"))
            .transpose()?,
    })
}

// Keep the covering-Commit lookup parameterized per current row. Flattening
// this into a hash join can read the Realm's entire immutable history just
// to materialize a small current cut. LIMIT 1 preserves the unique-id lookup
// and the LEFT JOIN still exposes missing provenance as NULL for validation.
pub(crate) const SNAPSHOT_CURRENT_SQL: &str = "SELECT result.*, covering.stream_ref AS source_stream_ref FROM ( \
         SELECT result_family AS selector_kind, NULL::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM realm_bootstrap_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'realm_authority_root'::text AS selector_kind, NULL::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, \
                jsonb_build_object('controller_actor_id',controller_actor_id, \
                    'controller_epoch',controller_epoch,'authority_generation',authority_generation, \
                    'authority_event_ref',authority_event_ref) AS value \
           FROM realm_authority_root_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'realm_policy_bundle'::text AS selector_kind, NULL::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM realm_policy_bundle_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'schema_definition'::text AS selector_kind, to_jsonb(schema_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM schema_definition_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'pin'::text AS selector_kind, pin_scope AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM pin_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'policy'::text AS selector_kind, to_jsonb(policy_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM policy_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'member_state'::text AS selector_kind, member_id::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM member_state_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'direct_conversation_binding'::text AS selector_kind, to_jsonb(pair_key) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM direct_conversation_binding_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'applet_registration'::text AS selector_kind, to_jsonb(applet_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM applet_registration_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'member_identity_updates'::text AS selector_kind, \
                jsonb_build_object('kind','member_identity_updates','member_id',member_id::jsonb,'segment',segment) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM member_identity_updates_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'sidecar'::text AS selector_kind, to_jsonb(sidecar_id) AS selector_subject, \
                current_commit_id,current_stream_position,value \
           FROM sidecar_current_results WHERE realm_id=$1 \
         UNION ALL \
         SELECT 'policy_action'::text AS selector_kind, \
                CASE subject_kind WHEN 'realm_action' THEN jsonb_build_object('kind','policy_action','branch','realm_action','action_id',subject_id) \
                  ELSE jsonb_build_object('kind','policy_action','branch','policy_ref','policy_id',subject_id,'action',action_key) END AS selector_subject, \
                current_commit_id,current_stream_position,value FROM policy_action_current_results WHERE realm_id=$1 \
         UNION ALL \
         SELECT 'sidecar_context'::text AS selector_kind, \
                jsonb_build_object('kind','sidecar_context','sidecar_id',sidecar_id,'source_context_ref',context_ref) AS selector_subject, \
                current_commit_id,current_stream_position,value \
           FROM sidecar_context_current_results WHERE realm_id=$1 \
         UNION ALL \
         SELECT 'agent_sidecar_exchange_controls'::text AS selector_kind, \
                jsonb_build_object('kind','agent_sidecar_exchange_controls','sidecar_id',sidecar_id,'source_context_ref',context_ref) AS selector_subject, \
                current_commit_id,current_stream_position,value \
           FROM sidecar_exchange_controls_current_results WHERE realm_id=$1 \
         UNION ALL \
         SELECT 'circle'::text AS selector_kind, to_jsonb(circle_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM circle_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'circle_member_state'::text AS selector_kind, \
                jsonb_build_object('kind','circle_member_state','circle_id',circle_id,'member_actor_id',member_id::jsonb) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM circle_member_state_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'call_state'::text AS selector_kind, to_jsonb(call_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM call_state_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'strand'::text AS selector_kind, to_jsonb(strand_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM strand_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'calendar_schedule_source'::text AS selector_kind, to_jsonb(strand_id) AS selector_subject, \
                current_commit_id,current_stream_position,calendar_schedule_source_value AS value \
           FROM strand_current_results WHERE realm_id=$1 AND calendar_schedule_source_value IS NOT NULL \
         UNION ALL \
         SELECT 'rsvp'::text AS selector_kind, \
                jsonb_build_object('kind','rsvp','event_ref',event_ref, \
                    'occurrence',occurrence,'responder_actor_id',responder_actor_id) AS selector_subject, \
                current_commit_id,current_stream_position,value \
           FROM rsvp_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'strand_watch'::text AS selector_kind, \
                jsonb_build_object('kind','strand_watch','strand_id',strand_id,'watcher_actor_id',watcher_actor_id::jsonb) AS selector_subject, \
                current_commit_id,current_stream_position,value \
           FROM strand_watch_current_results WHERE realm_id=$1 \
         UNION ALL \
         SELECT 'strand_position'::text AS selector_kind, \
                jsonb_build_object('kind','strand_position','board_space_id',board_space_id,'strand_id',strand_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM strand_position_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'space'::text AS selector_kind, to_jsonb(space_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM space_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'space_parent'::text AS selector_kind, to_jsonb(space_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM space_parent_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'space_child_scope_policy'::text AS selector_kind, to_jsonb(space_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM space_child_scope_policy_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'realm_set_default_strand'::text AS selector_kind, NULL::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM realm_set_default_strand_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'message_revision'::text AS selector_kind, to_jsonb(message_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM message_revision_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'mls_group'::text AS selector_kind, value->'effective_scope' AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM mls_group_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'moderation_report'::text AS selector_kind, to_jsonb(report_event_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM moderation_report_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'moderation_franking_proof'::text AS selector_kind, to_jsonb(target_event_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM moderation_franking_proof_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'moderation_state'::text AS selector_kind, to_jsonb(target_ref) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM moderation_state_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'object_redaction'::text AS selector_kind, to_jsonb(target_ref) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM object_redaction_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'message_reactions'::text AS selector_kind, to_jsonb(target_ref) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM message_reactions_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'invite_lifecycle'::text AS selector_kind, to_jsonb(invite_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM invite_lifecycle_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'invite_live_target'::text AS selector_kind, invitee_account_id::jsonb AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM invite_live_target_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'invite_directed_invitee'::text AS selector_kind, to_jsonb(invite_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM invite_directed_invitee_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'capability_grant'::text AS selector_kind, to_jsonb(grant_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM capability_grant_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'realm_organization'::text AS selector_kind, \
                jsonb_build_object('kind','realm_organization','organization_id',organization_id,'relationship',relationship) AS selector_subject, \
                current_commit_id,current_stream_position,value \
           FROM realm_organization_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'mimi_room_binding'::text AS selector_kind, to_jsonb(mimi_room_uri) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM mimi_room_binding_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'agent_interaction'::text AS selector_kind, jsonb_build_object('kind','agent_interaction','agent_account_id',agent_account_id) AS selector_subject, \
                current_commit_id,current_stream_position,value \
           FROM agent_interaction_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'agent_status'::text AS selector_kind, to_jsonb(agent_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM agent_status_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT 'agent_key'::text AS selector_kind, jsonb_build_object('agent_id',agent_id,'agent_key_id',agent_key_id) AS selector_subject, \
                current_commit_id, current_stream_position, value \
           FROM agent_key_current_results WHERE realm_id = $1 \
         ) result LEFT JOIN LATERAL ( \
           SELECT stream_ref FROM realm_commits \
           WHERE commit_id=result.current_commit_id \
             AND stream_position=result.current_stream_position \
             AND realm_id=$1 LIMIT 1) covering ON TRUE";

pub(crate) async fn realm_state_snapshot_material_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<coland_storage::RealmStateSnapshotMaterial>> {
    let authority = sql_query(
        "SELECT realm_id, generation, service_id, authority_ref, last_handoff_ref \
         FROM realm_authorities WHERE realm_id = $1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<AuthorityRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(authority_from_row)
    .transpose()?;
    let Some(authority) = authority else {
        return Ok(None);
    };

    let rows = sql_query(REALM_STREAM_HEADS_SQL)
        .bind::<Text, _>(realm_id.as_str())
        .load::<HeadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let mut heads = rows
        .into_iter()
        .map(|row| {
            Ok(arkret_wire::CommitStreamHead {
                stream_ref: decode_json(row.stream_ref, "commit stream ref")?,
                stream_position: to_u64(row.stream_position, "stream position")?,
                commit_id: decode_text(row.commit_id, "RealmCommit id")?,
            })
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    heads.sort_by(|left, right| left.stream_ref.cmp(&right.stream_ref));

    let rows = sql_query(SNAPSHOT_CURRENT_SQL)
        .bind::<Text, _>(realm_id.as_str())
        .load::<SnapshotCurrentRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    // A bootstrap installs verified current rows whose source Commit may be
    // below this member's history floor. Their exact durable replica evidence
    // supplies the source only while its verified cut equals the held head.
    let replica_evidence =
        crate::replica_authorization::snapshot_current_evidence(conn, realm_id, &heads).await?;
    let mut current_state_entries = rows
        .into_iter()
        .map(|row| {
            let selector = match (row.selector_kind.as_str(), row.selector_subject) {
                ("realm_genesis", None) => arkret_wire::CurrentSelector::RealmGenesis,
                ("realm_tombstone", None) => arkret_wire::CurrentSelector::RealmTombstone,
                ("realm_archive", None) => arkret_wire::CurrentSelector::RealmArchive,
                ("realm_freeze", None) => arkret_wire::CurrentSelector::RealmFreeze,
                ("realm_authority_root", None) => arkret_wire::CurrentSelector::RealmAuthorityRoot,
                ("realm_profile", None) => arkret_wire::CurrentSelector::RealmProfile,
                ("realm_preview_policy", None) => arkret_wire::CurrentSelector::RealmPreviewPolicy,
                ("realm_policy_bundle", None) => arkret_wire::CurrentSelector::RealmPolicyBundle,
                ("schema_definition", Some(schema_id)) => arkret_wire::CurrentSelector::SchemaDefinition {
                    schema_id: serde_json::from_value(schema_id).map_err(PersistenceError::database)?,
                },
                ("pin", Some(pin_scope)) => arkret_wire::CurrentSelector::Pin {
                    pin_scope: serde_json::from_value(pin_scope).map_err(PersistenceError::database)?,
                },
                ("policy", Some(policy_id)) => arkret_wire::CurrentSelector::Policy {
                    policy_id: serde_json::from_value(policy_id).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored Policy selector identity is invalid: {error}"
                        ))
                    })?,
                },
                ("sidecar", Some(sidecar_id)) => arkret_wire::CurrentSelector::Sidecar {
                    sidecar_id: serde_json::from_value(sidecar_id).map_err(PersistenceError::database)?,
                },
                ("policy_action", Some(subject)) => serde_json::from_value(subject).map_err(PersistenceError::database)?,
                ("sidecar_context" | "agent_sidecar_exchange_controls", Some(selector)) => serde_json::from_value(selector).map_err(PersistenceError::database)?,
                ("realm_join_rule", None) => arkret_wire::CurrentSelector::RealmJoinRule,
                ("realm_history_access", None) => arkret_wire::CurrentSelector::RealmHistoryAccess,
                ("realm_read_receipt_policy", None) => arkret_wire::CurrentSelector::RealmReadReceiptPolicy,
                ("realm_discovery", None) => arkret_wire::CurrentSelector::RealmDiscovery,
                ("realm_alias", None) => arkret_wire::CurrentSelector::RealmAlias,
                ("realm_plaintext_visible_services", None) => {
                    arkret_wire::CurrentSelector::RealmPlaintextVisibleServices
                }
                ("realm_set_default_strand", None) => {
                    arkret_wire::CurrentSelector::RealmSetDefaultStrand
                }
                ("member_state", Some(actor_id)) => arkret_wire::CurrentSelector::MemberState {
                    actor_id: serde_json::from_value(actor_id).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored snapshot member actor id is invalid: {error}"
                        ))
                    })?,
                },
                ("direct_conversation_binding", Some(pair_key)) => arkret_wire::CurrentSelector::DirectConversationBinding {
                    pair_key: serde_json::from_value(pair_key).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored Direct Conversation pair key is invalid: {error}"
                        ))
                    })?,
                },
                ("member_identity_updates", Some(selector)) => serde_json::from_value::<arkret_wire::CurrentSelector>(selector)
                    .map_err(|error| PersistenceError::Internal(format!("stored member identity selector is invalid: {error}")))?,
                ("applet_registration", Some(applet_id)) => arkret_wire::CurrentSelector::AppletRegistration {
                    applet_id: serde_json::from_value(applet_id).map_err(PersistenceError::database)?,
                },
                ("circle", Some(circle_id)) => arkret_wire::CurrentSelector::Circle {
                    circle_id: serde_json::from_value(circle_id).map_err(|error| {
                        PersistenceError::Internal(format!("stored Circle selector identity is invalid: {error}"))
                    })?,
                },
                ("circle_member_state", Some(selector)) => serde_json::from_value::<arkret_wire::CurrentSelector>(selector)
                    .map_err(|error| PersistenceError::Internal(format!("stored Circle member selector is invalid: {error}")))?,
                ("call_state", Some(call_id)) => arkret_wire::CurrentSelector::CallState {
                    call_id: serde_json::from_value(call_id).map_err(PersistenceError::database)?,
                },
                ("strand", Some(strand_id)) => arkret_wire::CurrentSelector::Strand {
                    strand_id: serde_json::from_value(strand_id).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored Strand selector identity is invalid: {error}"
                        ))
                    })?,
                },
                ("calendar_schedule_source", Some(strand_id)) => arkret_wire::CurrentSelector::CalendarScheduleSource {
                    strand_id: serde_json::from_value(strand_id).map_err(PersistenceError::database)?,
                },
                ("rsvp", Some(selector)) => {
                    serde_json::from_value::<arkret_wire::CurrentSelector>(selector)
                        .map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored RSVP selector is invalid: {error}"
                            ))
                        })?
                }
                ("strand_position", Some(selector)) => {
                    serde_json::from_value::<arkret_wire::CurrentSelector>(selector)
                        .map_err(PersistenceError::database)?
                }
                ("space", Some(space_id)) => arkret_wire::CurrentSelector::Space {
                    space_id: serde_json::from_value(space_id).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored Space selector identity is invalid: {error}"
                        ))
                    })?,
                },
                ("space_parent", Some(space_id)) => arkret_wire::CurrentSelector::SpaceParent {
                    space_id: serde_json::from_value(space_id).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored Space parent selector identity is invalid: {error}"
                        ))
                    })?,
                },
                ("space_child_scope_policy", Some(space_id)) => {
                    arkret_wire::CurrentSelector::SpaceChildScopePolicy {
                        space_id: serde_json::from_value(space_id).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored Space policy selector identity is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("strand_watch", Some(subject)) => serde_json::from_value(subject).map_err(PersistenceError::database)?,
                ("message_revision", Some(message_id)) => {
                    arkret_wire::CurrentSelector::MessageRevision {
                        message_id: serde_json::from_value(message_id).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored Message revision selector identity is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("mls_group", Some(scope_ref)) => arkret_wire::CurrentSelector::MlsGroup {
                    scope_ref: serde_json::from_value(scope_ref).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored mls_group scope is invalid: {error}"
                        ))
                    })?,
                },
                ("moderation_report", Some(event_id)) => {
                    arkret_wire::CurrentSelector::ModerationReport {
                        event_id: serde_json::from_value(event_id).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored moderation report selector identity is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("moderation_franking_proof", Some(event_id)) => {
                    arkret_wire::CurrentSelector::ModerationFrankingProof {
                        event_id: serde_json::from_value(event_id).map_err(PersistenceError::database)?,
                    }
                }
                ("realm_organization", Some(selector)) => {
                    serde_json::from_value::<arkret_wire::CurrentSelector>(selector)
                        .map_err(PersistenceError::database)?
                }
                ("moderation_state", Some(target_ref)) => {
                    arkret_wire::CurrentSelector::ModerationState {
                        target_ref: serde_json::from_value(target_ref).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored moderation_state target is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("object_redaction", Some(target_ref)) => {
                    arkret_wire::CurrentSelector::ObjectRedaction {
                        target_ref: serde_json::from_value(target_ref).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored object_redaction target is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("message_reactions", Some(target_ref)) => {
                    let target_ref = target_ref.as_str().ok_or_else(|| {
                        PersistenceError::Internal(
                            "stored message_reactions target is not a string".to_owned(),
                        )
                    })?;
                    if !arkret_wire::is_object_ref(target_ref) {
                        return Err(PersistenceError::Internal(
                            "stored message_reactions target is not a formal object_ref"
                                .to_owned(),
                        ));
                    }
                    arkret_wire::CurrentSelector::MessageReactions {
                        target_ref: target_ref.to_owned(),
                    }
                }
                ("invite_lifecycle", Some(invite_id)) => {
                    arkret_wire::CurrentSelector::InviteLifecycle {
                        invite_id: serde_json::from_value(invite_id).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored invite_lifecycle selector identity is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("invite_live_target", Some(invitee_account_id)) => {
                    arkret_wire::CurrentSelector::InviteLiveTarget {
                        invitee_account_id: serde_json::from_value(invitee_account_id).map_err(
                            |error| {
                                PersistenceError::Internal(format!(
                                    "stored invite_live_target selector identity is invalid: {error}"
                                ))
                            },
                        )?,
                    }
                }
                ("invite_directed_invitee", Some(invite_id)) => {
                    arkret_wire::CurrentSelector::InviteDirectedInvitee {
                        invite_id: serde_json::from_value(invite_id).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored invite_directed_invitee selector identity is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("capability_grant", Some(grant_id)) => {
                    arkret_wire::CurrentSelector::CapabilityGrant {
                        grant_id: serde_json::from_value(grant_id).map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored capability_grant selector identity is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("mimi_room_binding", Some(room_uri)) => {
                    arkret_wire::CurrentSelector::MimiRoomBinding {
                        mimi_room_uri: arkret_wire::MimiRoomUri::new(
                            room_uri.as_str().ok_or_else(|| {
                                PersistenceError::Internal(
                                    "stored MIMI room URI is not a string".to_owned(),
                                )
                            })?,
                        )
                        .map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored snapshot MIMI room URI is invalid: {error}"
                            ))
                        })?,
                    }
                }
                ("agent_interaction", Some(subject)) => serde_json::from_value(subject).map_err(PersistenceError::database)?,
                ("agent_status", Some(agent_id)) => arkret_wire::CurrentSelector::AgentStatus {
                    agent_id: serde_json::from_value(agent_id).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored Agent status identity is invalid: {error}"
                        ))
                    })?,
                },
                ("agent_key", Some(subject)) => {
                    let mut selector = subject
                        .as_object()
                        .ok_or_else(|| {
                            PersistenceError::Internal(
                                "stored Agent key selector is invalid".to_owned(),
                            )
                        })?
                        .clone();
                    selector.insert("kind".to_owned(), Value::String("agent_key".to_owned()));
                    serde_json::from_value(Value::Object(selector)).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored Agent key selector is invalid: {error}"
                        ))
                    })?
                }
                _ => {
                    return Err(PersistenceError::Internal(
                        "stored snapshot current selector is invalid".to_owned(),
                    ));
                }
            };
            let revision = arkret_wire::CurrentRevision {
                    commit_id: decode_text(row.current_commit_id, "current RealmCommit id")?,
                    stream_position: to_u64(
                        row.current_stream_position,
                        "current stream position",
                    )?,
                };
            let source_stream_ref = match row.source_stream_ref {
                Some(source) => decode_json(source, "current source stream ref")?,
                None => replica_evidence.iter().find_map(|entry| {
                    let arkret_wire::TypedCurrentRow::Value {
                        selector: proved_selector, source_stream_ref, revision: proved_revision, value,
                    } = entry;
                    (proved_selector == &selector && proved_revision == &revision && value == &row.value)
                        .then(|| source_stream_ref.clone())
                }).ok_or_else(|| PersistenceError::SchemaViolation(
                    "snapshot current result has neither its covering Commit nor exact verified replica evidence".to_owned(),
                ))?,
            };
            Ok(arkret_wire::TypedCurrentRow::Value {
                selector, source_stream_ref, revision,
                value: row.value,
            })
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    // These public result values are proved by the original snapshot, but do
    // not carry the private admission provenance required by governing tables.
    // Preserve them as read evidence without manufacturing those tables.
    for entry in replica_evidence {
        let arkret_wire::TypedCurrentRow::Value { selector, .. } = &entry;
        if matches!(
            selector,
            arkret_wire::CurrentSelector::RealmAuthorityRoot
                | arkret_wire::CurrentSelector::CapabilityGrant { .. }
                | arkret_wire::CurrentSelector::InviteLifecycle { .. }
                | arkret_wire::CurrentSelector::InviteLiveTarget { .. }
                | arkret_wire::CurrentSelector::InviteDirectedInvitee { .. }
                | arkret_wire::CurrentSelector::MlsGroup { .. }
        ) && !current_state_entries.iter().any(|current| {
            let arkret_wire::TypedCurrentRow::Value {
                selector: current_selector,
                ..
            } = current;
            current_selector == selector
        }) {
            current_state_entries.push(entry);
        }
    }
    current_state_entries.extend(
        crate::relation_current_results::snapshot_rows_in_connection(conn, realm_id).await?,
    );
    let mut keyed_entries = current_state_entries
        .into_iter()
        .map(|entry| {
            let key = arkret_canonical::canonical_json_bytes(&entry)
                .map_err(PersistenceError::database)?;
            Ok((key, entry))
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    keyed_entries.sort_by(|left, right| left.0.cmp(&right.0));
    let current_state_entries: Vec<_> = keyed_entries.into_iter().map(|(_, entry)| entry).collect();
    let history_access = current_state_entries
        .iter()
        .find_map(|entry| match entry {
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::RealmHistoryAccess,
                value,
                ..
            } => Some(value),
            _ => None,
        })
        .map(|value| {
            serde_json::from_value::<arkret_wire::HistoryAccess>(value.clone()).map_err(|error| {
                PersistenceError::Internal(format!(
                    "stored Realm history access is invalid: {error}"
                ))
            })
        })
        .transpose()?
        .unwrap_or(arkret_wire::HistoryAccess::AllHistoryForCurrentMembers);
    let stream_floors = heads
        .iter()
        .map(|head| arkret_wire::StreamHistoryFloor {
            stream_ref: head.stream_ref.clone(),
            oldest_position: 0,
        })
        .collect();
    Ok(Some(coland_storage::RealmStateSnapshotMaterial {
        realm_id: realm_id.clone(),
        governance_generation: authority.generation,
        visible_stream_heads: heads,
        current_state_entries,
        retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
            history_access,
            stream_floors,
        },
    }))
}

pub(crate) async fn locked_authority(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> Result<Option<CurrentRealmAuthority>, PgTransactionError> {
    let row = sql_query(
        "SELECT realm_id, generation, service_id, authority_ref, last_handoff_ref \
         FROM realm_authorities WHERE realm_id = $1 FOR UPDATE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<AuthorityRow>(conn)
    .await
    .optional()?;
    row.map(authority_from_row).transpose().map_err(Into::into)
}

fn same_authority(left: &CurrentRealmAuthority, right: &CurrentRealmAuthority) -> bool {
    left.realm_id == right.realm_id
        && left.generation == right.generation
        && left.service_id == right.service_id
        && left.authority_ref == right.authority_ref
        && left.last_handoff_ref == right.last_handoff_ref
}

/// A committed change freezes every stream of its outgoing tenure. The
/// authority row is already locked, so change admission and every writer
/// have one linearization point; an exact accepted replay remains readable.
async fn require_planned_handoff_write_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    current: &CurrentRealmAuthority,
) -> PersistenceResult<()> {
    let pending = sql_query(
        "SELECT EXISTS(SELECT 1 FROM realm_commits c \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND c.governance_generation=$2 \
           AND e.kind='ak.realm.governance_station.change') AS present",
    )
    .bind::<Text, _>(current.realm_id.as_str())
    .bind::<BigInt, _>(to_i64(current.generation, "governance generation")?)
    .get_result::<PresenceRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if pending.present {
        return Err(PersistenceError::Conflict(
            "temporarily_unavailable: the outgoing authority tenure is frozen for planned handoff"
                .into(),
        ));
    }
    if event.kind != arkret_wire::EventKind::RealmGovernanceStationChange {
        return Ok(());
    }
    let payload: arkret_models_collaboration::events_payloads::RealmGovernanceStationChangePayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(invalid)?;
    let head = sql_query(
        "SELECT commit_json FROM realm_commits WHERE realm_id=$1 AND stream_key=$2 \
         ORDER BY stream_position DESC LIMIT 1",
    )
    .bind::<Text, _>(current.realm_id.as_str())
    .bind::<Text, _>(stream_key(&arkret_wire::CommitStreamRef::Realm {
        realm_id: current.realm_id.clone(),
    })?)
    .get_result::<CommitRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let head = head
        .map(|row| decode_json::<arkret_wire::RealmCommit>(row.commit_json, "Realm stream head"))
        .transpose()?;
    if payload.expected_governance_generation != current.generation
        || head.as_ref().map(|head| &head.commit_id)
            != Some(&payload.expected_realm_stream_commit_id)
        || payload.new_governance_station_id == current.service_id
    {
        return Err(PersistenceError::Conflict(
            "failed_precondition: planned handoff does not match the current authority and Realm head"
                .into(),
        ));
    }
    Ok(())
}

fn signature_service_id(
    signature: &arkret_wire::DetachedObjectSignature,
) -> PersistenceResult<arkret_wire::DidCoreId> {
    let controller = signature
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| invalid("authority signature method has no fragment"))?;
    let did = arkret_wire::Did::new(controller.to_owned()).map_err(invalid)?;
    arkret_identifiers::project_did_to_core_id(&did).map_err(invalid)
}

async fn handoff_originals_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Vec<arkret_wire::CommittedEventFullView>> {
    let rows = sql_query(
        "SELECT c.commit_json,e.envelope FROM realm_commits c \
         LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
         WHERE c.realm_id=$1 ORDER BY c.stream_key,c.stream_position",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<StreamPageRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut fulls = Vec::with_capacity(rows.len());
    let mut previous: Option<arkret_wire::RealmCommit> = None;
    for row in rows {
        let full = arkret_wire::CommittedEventFullView {
            event: decode_json(
                row.envelope
                    .ok_or_else(|| invalid("handoff requires every original Event"))?,
                "handoff Event",
            )?,
            commit: decode_json(row.commit_json, "handoff Commit")?,
        };
        full.validate_shape().map_err(invalid)?;
        full.event
            .verify_event_id_matches_content_with_digest_suite(
                full.event.event_id.digest_suite_code().digest_suite(),
            )
            .map_err(invalid)?;
        full.commit
            .verify_commit_id_matches_content()
            .map_err(invalid)?;
        if previous
            .as_ref()
            .is_some_and(|previous| previous.stream_ref == full.commit.stream_ref)
        {
            full.commit
                .validate_successor_of(previous.as_ref().unwrap())
                .map_err(invalid)?;
        } else if full.commit.stream_position != 0 || full.commit.previous_commit_ref.is_some() {
            return Err(invalid(
                "handoff requires a complete genesis-to-head chain for every stream",
            ));
        }
        previous = Some(full.commit.clone());
        fulls.push(full);
    }
    Ok(fulls)
}

async fn handoff_inventory_in_connection(
    conn: &mut AsyncPgConnection,
    fulls: &[arkret_wire::CommittedEventFullView],
) -> PersistenceResult<
    Vec<arkret_models_collaboration::authority_commit::HistoricalProducerSignerFactEntry>,
> {
    use arkret_models_collaboration::authority_commit::HistoricalProducerSignerFactEntry;
    let mut entries = Vec::new();
    for full in fulls
        .iter()
        .filter(|full| full.commit.producer_signer_fact_digest.is_some())
    {
        let fact = crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
            conn,
            &full.event,
            &full.commit,
        )
        .await?
        .ok_or_else(|| invalid("handoff original is missing its immutable signer fact"))?;
        entries.push(HistoricalProducerSignerFactEntry {
            target: arkret_wire::CommittedEventRef {
                event_id: full.event.event_id.clone(),
                commit_id: full.commit.commit_id.clone(),
                stream_ref: full.commit.stream_ref.clone(),
                stream_position: full.commit.stream_position,
            },
            producer_signer_fact: fact,
        });
    }
    let mut keyed = entries
        .into_iter()
        .map(|entry| {
            Ok((
                (
                    arkret_canonical::canonical_json_bytes(&entry.target.stream_ref)
                        .map_err(PersistenceError::database)?,
                    entry.target.stream_position,
                    entry.target.event_id.to_string(),
                    entry.target.commit_id.to_string(),
                ),
                entry,
            ))
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(keyed.into_iter().map(|(_, entry)| entry).collect())
}

/// Queue one producer Event on a caller-owned connection.
///
/// A Station that admits and commits in a single transaction calls this
/// immediately before [`commit_transaction_in_connection`], so the queued row
/// and its `RealmCommit` become visible together or not at all.
pub(crate) async fn queue_event_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    queued_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), PgTransactionError> {
    event.validate_for_submit_structural().map_err(invalid)?;
    let canonical_bytes =
        arkret_canonical::canonical_json_bytes(&event.digest_payload().map_err(invalid)?)
            .map_err(PersistenceError::database)?;
    let envelope = serde_json::to_value(event).map_err(PersistenceError::database)?;
    let token = ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| invalid("Event id is not a canonical Event token"))?;
    let realm_pk = crate::realm_identity::ensure_realm_pk(conn, event.realm_id.as_str()).await?;
    let digest_suite = i16::from(token[0] & 0x0f);
    let existing = sql_query(
        "SELECT pk AS event_pk, state, canonical_bytes, envelope \
         FROM canonical_events WHERE id = $1 FOR UPDATE",
    )
    .bind::<Binary, _>(token.to_vec())
    .get_result::<EventPkRow>(&mut *conn)
    .await
    .optional()?;
    if let Some(existing) = existing {
        if existing.canonical_bytes == canonical_bytes && existing.envelope == envelope {
            return Ok(());
        }
        return Err(PersistenceError::Conflict("event_hash_collision".into()).into());
    }
    sql_query(
        "INSERT INTO canonical_events \
         (id, digest_suite, digest, actor_id, realm_id, realm_pk, scope_ref, kind, canonical_bytes, envelope, state, received_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'queued', $11)",
    )
    .bind::<Binary, _>(token.to_vec())
    .bind::<SmallInt, _>(digest_suite)
    .bind::<Binary, _>(token[1..].to_vec())
    .bind::<Text, _>(event.actor_id.to_string())
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<BigInt, _>(realm_pk)
    .bind::<Jsonb, _>(serde_json::to_value(&event.scope_ref).map_err(PersistenceError::database)?)
    .bind::<Text, _>(event.kind.as_str())
    .bind::<Binary, _>(canonical_bytes)
    .bind::<Jsonb, _>(envelope)
    .bind::<Timestamptz, _>(queued_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Installs one authority decision on an existing database transaction.
///
/// Product projections, delivery intents, and the accepted `RealmCommit` must
/// share this connection so a caller can expose either the complete accepted
/// operation or none of it.
pub(crate) async fn commit_transaction_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(conn, transaction, VerifiedPcrUnit::None)
        .await
}

/// Only the registered PCR genesis, recovery and accepted-device UoWs may
/// call this after they validate the Event/Commit and its authority proof.
pub(crate) async fn commit_verified_pcr_device_transaction_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(conn, transaction, VerifiedPcrUnit::Device)
        .await
}

/// Only the SecurityRotation proposal unit may call this after rechecking the
/// authorizing device against the typed PCR current cut under authority lock.
pub(crate) async fn commit_verified_pcr_revoke_proposal_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::RevokeProposal,
    )
    .await
}

/// Only the KeyBackup pointer unit may call this after rechecking the signing
/// device, generation, source checkpoint and record signature under the PCR
/// authority lock; the same transaction then projects the pointer and marker.
pub(crate) async fn commit_verified_key_backup_pointer_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::KeyBackupPointer,
    )
    .await
}

/// Only the recovery policy publication unit may call this after rechecking
/// the signing device, the version ratchet and the policy signature under the
/// PCR authority lock; the same transaction then records the accepted policy.
pub(crate) async fn commit_verified_recovery_policy_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::RecoveryPolicy,
    )
    .await
}

/// Only the Agent provision unit may call this after rechecking the signing
/// device, the envelope binding and both declarations under the controller
/// PCR authority lock; the same transaction then writes the four results.
pub(crate) async fn commit_verified_agent_provision_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::AgentProvision,
    )
    .await
}

/// Only the Agent control unit may call this after the provision binding,
/// the controller device cut and the kind's gate under the Agent PCR lock.
pub(crate) async fn commit_verified_agent_control_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::AgentControl,
    )
    .await
}

/// Only the Agent PCR genesis unit may call this after the provision
/// declaration reverse lookup and the controller device cut.
pub(crate) async fn commit_verified_agent_pcr_genesis_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::AgentPcrGenesis,
    )
    .await
}

/// Only the Actor Profile and accountability grant units may call this after
/// rechecking the signing device and the kind's same-cut admission under the
/// PCR authority lock; the same transaction then writes the typed result.
pub(crate) async fn commit_verified_pcr_typed_current_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(
        conn,
        transaction,
        VerifiedPcrUnit::ProfileOrAccountability,
    )
    .await
}

/// The registered PCR unit whose same-cut checks already ran on this
/// connection. Generic admission is `None` and cannot write these kinds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum VerifiedPcrUnit {
    None,
    Device,
    RevokeProposal,
    KeyBackupPointer,
    RecoveryPolicy,
    ProfileOrAccountability,
    AgentProvision,
    AgentPcrGenesis,
    AgentControl,
    Consent,
    Applet,
}

/// The closed Applet authoring aggregate independently verifies its fixed set
/// before writing accepted Events and their typed results on this connection.
pub(crate) async fn commit_verified_applet_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(conn, transaction, VerifiedPcrUnit::Applet)
        .await
}

pub(crate) async fn commit_verified_consent_in_connection(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    commit_transaction_in_connection_with_device_guard(conn, transaction, VerifiedPcrUnit::Consent)
        .await
}

fn is_agent_pcr_genesis(event: &arkret_wire::Event) -> bool {
    event.kind == arkret_wire::EventKind::RealmCreate
        && event
            .payload
            .get("object")
            .and_then(|object| object.get("purpose"))
            .and_then(serde_json::Value::as_str)
            == Some("agent_control")
}

fn is_recovery_policy_set(event: &arkret_wire::Event) -> bool {
    event.kind == arkret_wire::EventKind::PolicySet
        && event
            .payload
            .get("value")
            .and_then(|value| value.get("schema"))
            .and_then(serde_json::Value::as_str)
            == Some(arkret_wire::SchemaId::RECOVERY_POLICY_V1)
}

fn commit_transaction_in_connection_with_device_guard<'a>(
    conn: &'a mut AsyncPgConnection,
    transaction: &'a AuthorityCommitTransaction,
    verified_unit: VerifiedPcrUnit,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<AuthorityCommitWriteOutcome, PgTransactionError>>
            + Send
            + 'a,
    >,
> {
    Box::pin(commit_transaction_with_device_guard_inner(
        conn,
        transaction,
        verified_unit,
    ))
}

async fn commit_transaction_with_device_guard_inner(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    verified_unit: VerifiedPcrUnit,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    let verified_pcr_device_unit = verified_unit == VerifiedPcrUnit::Device;
    let verified_pcr_revoke_unit = verified_unit == VerifiedPcrUnit::RevokeProposal;
    if matches!(
        transaction.event.kind,
        arkret_wire::EventKind::ConsentGrant | arkret_wire::EventKind::ConsentRevoke
    ) && verified_unit != VerifiedPcrUnit::Consent
    {
        return Err(PersistenceError::Conflict("consent_current_unit_required".to_owned()).into());
    }
    // The pointer's own signature, accepted device authorization, current
    // generation and source checkpoint are rechecked only by the registered
    // pointer unit; generic Event admission must not publish an unchecked
    // pointer.
    if transaction.event.kind == arkret_wire::EventKind::KeyBackupActiveSeries
        && verified_unit != VerifiedPcrUnit::KeyBackupPointer
    {
        return Err(PersistenceError::Conflict(
            "key_backup_active_series_current_device_authority_unavailable".to_owned(),
        )
        .into());
    }
    // A recovery policy is PCR control state; only its publication unit, which
    // records the accepted policy in the same transaction, may commit it.
    if is_recovery_policy_set(&transaction.event)
        && verified_unit != VerifiedPcrUnit::RecoveryPolicy
    {
        return Err(PersistenceError::Conflict(
            "recovery_policy_publication_unit_required".to_owned(),
        )
        .into());
    }
    // Profile and accountability results are PCR typed current written only
    // by their units, which decide the signer and the accountability cut.
    if matches!(
        transaction.event.kind,
        arkret_wire::EventKind::ProfileCreate
            | arkret_wire::EventKind::ProfileUpdate
            | arkret_wire::EventKind::IdentityAccountabilityGrant
    ) && !matches!(
        verified_unit,
        VerifiedPcrUnit::ProfileOrAccountability | VerifiedPcrUnit::Applet
    ) && !(verified_unit == VerifiedPcrUnit::AgentControl
        && crate::agent_control::is_agent_control_event(&transaction.event))
    {
        return Err(PersistenceError::Conflict(
            "actor_profile_or_accountability_unit_required".to_owned(),
        )
        .into());
    }
    let applet_genesis = transaction.event.kind == arkret_wire::EventKind::RealmCreate
        && transaction
            .event
            .payload
            .get("object")
            .and_then(|object| object.get("purpose"))
            .and_then(serde_json::Value::as_str)
            == Some("applet_managed_control");
    if (applet_genesis
        || matches!(
            transaction.event.kind,
            arkret_wire::EventKind::AppletRegistration
                | arkret_wire::EventKind::AppletManagedActorProvision
        ))
        && verified_unit != VerifiedPcrUnit::Applet
    {
        return Err(PersistenceError::Conflict("applet_authoring_unit_required".to_owned()).into());
    }
    // An Agent PCR genesis is admitted only by the unit that reverse-looks-up
    // its accepted provision declaration (key-management.md section 3.6.3).
    if is_agent_pcr_genesis(&transaction.event) && verified_unit != VerifiedPcrUnit::AgentPcrGenesis
    {
        return Err(
            PersistenceError::Conflict("agent_pcr_genesis_unit_required".to_owned()).into(),
        );
    }
    // Agent key and lifecycle Events decide the controller delegation and
    // the Agent's current key set and lifecycle at one Agent PCR cut; only
    // their unit may commit them.
    if crate::agent_control::is_agent_control_event(&transaction.event)
        && verified_unit != VerifiedPcrUnit::AgentControl
    {
        return Err(PersistenceError::Conflict("agent_control_unit_required".to_owned()).into());
    }
    // ak.agent.provision projects four typed results atomically
    // (key-management.md section 3.6.3); only its unit writes that set.
    if transaction.event.kind == arkret_wire::EventKind::AgentProvision
        && verified_unit != VerifiedPcrUnit::AgentProvision
    {
        return Err(
            PersistenceError::Conflict("agent_provision_atomic_unit_required".to_owned()).into(),
        );
    }
    // No registered atomic revoke UoW yet writes the immutable proposal dot
    // and covering command result. Do not accept an Event that read-side
    // device status cannot fold at the same authority cut.
    if transaction.event.kind == arkret_wire::EventKind::DeviceRevoke && !verified_pcr_revoke_unit {
        return Err(PersistenceError::Conflict(
            "pcr_device_revocation_current_authority_unavailable".to_owned(),
        )
        .into());
    }
    if matches!(
        transaction.event.kind,
        arkret_wire::EventKind::DeviceAuthorize | arkret_wire::EventKind::DeviceReanchor
    ) && !verified_pcr_device_unit
    {
        return Err(PersistenceError::Conflict(
            "pcr_device_current_authority_unavailable".to_owned(),
        )
        .into());
    }

    transaction.validate().map_err(invalid)?;
    if signature_service_id(&transaction.commit.signature)?
        != transaction.expected_authority.service_id
    {
        return Err(invalid(
            "RealmCommit signature method does not belong to the expected authority",
        )
        .into());
    }
    let canonical_bytes = arkret_canonical::canonical_json_bytes(
        &transaction.event.digest_payload().map_err(invalid)?,
    )
    .map_err(PersistenceError::database)?;
    let event_token = ids::parse_event_id(transaction.event.event_id.as_str())
        .ok_or_else(|| invalid("Event id is not a canonical Event token"))?;
    let stream_key = stream_key(&transaction.commit.stream_ref)?;
    let commit_json =
        serde_json::to_value(&transaction.commit).map_err(PersistenceError::database)?;
    let stream_position = to_i64(transaction.commit.stream_position, "stream position")?;
    let governance_generation = to_i64(
        transaction.commit.governance_generation,
        "governance generation",
    )?;

    let current = locked_authority(conn, &transaction.expected_authority.realm_id)
        .await?
        .ok_or_else(|| PersistenceError::NotFound("Realm authority not initialized".into()))?;
    if !same_authority(&current, &transaction.expected_authority) {
        return Ok(AuthorityCommitWriteOutcome::StaleAuthority(current));
    }

    let event_row = sql_query(
        "SELECT pk AS event_pk, state, canonical_bytes, envelope \
         FROM canonical_events WHERE id = $1 FOR UPDATE",
    )
    .bind::<Binary, _>(event_token.to_vec())
    .get_result::<EventPkRow>(&mut *conn)
    .await
    .optional()?
    .ok_or_else(|| PersistenceError::NotFound("queued Event not found".into()))?;
    if event_row.canonical_bytes != canonical_bytes
        || event_row.envelope
            != serde_json::to_value(&transaction.event).map_err(PersistenceError::database)?
    {
        return Err(PersistenceError::Conflict("event_hash_collision".into()).into());
    }

    let existing = sql_query("SELECT commit_json FROM realm_commits WHERE event_pk = $1")
        .bind::<BigInt, _>(event_row.event_pk)
        .get_result::<CommitRow>(&mut *conn)
        .await
        .optional()?;
    if let Some(existing) = existing {
        require_exact_commit_replay(&existing.commit_json, &commit_json)?;
        return Ok(AuthorityCommitWriteOutcome::Duplicate);
    }
    if event_row.state != "queued" {
        return Err(PersistenceError::Conflict(format!(
            "Event cannot commit from state {}",
            event_row.state
        ))
        .into());
    }

    crate::realm_authorization_cut::require_commit_lifecycle_in_connection(
        conn,
        &transaction.event,
        transaction.commit.committed_at,
    )
    .await?;

    require_planned_handoff_write_in_connection(conn, &transaction.event, &current).await?;

    let previous = sql_query(
        "SELECT commit_json FROM realm_commits \
         WHERE stream_key = $1 ORDER BY stream_position DESC LIMIT 1 FOR UPDATE",
    )
    .bind::<Text, _>(&stream_key)
    .get_result::<CommitRow>(&mut *conn)
    .await
    .optional()?;
    match previous {
        Some(previous) => {
            let previous_commit: arkret_wire::RealmCommit =
                decode_json(previous.commit_json, "previous RealmCommit")?;
            // The Station assigns the order (authority-commit-log.md §2/§4):
            // another Commit won this stream after the candidate was built on
            // an older head. Nothing is committed and the exact Event may be
            // retried, so this is `retryable_unavailable`, never a schema fault.
            if previous_commit.stream_ref == transaction.commit.stream_ref
                && previous_commit.stream_position >= transaction.commit.stream_position
            {
                return Err(PersistenceError::Conflict(format!(
                    "{}: stream head advanced to position {} before this RealmCommit",
                    coland_storage::ConflictCode::TemporarilyUnavailable.as_str(),
                    previous_commit.stream_position
                ))
                .into());
            }
            transaction
                .commit
                .validate_successor_of(&previous_commit)
                .map_err(invalid)?;
        }
        None if transaction.commit.stream_position == 0
            && transaction.commit.previous_commit_ref.is_none() => {}
        None => {
            return Err(PersistenceError::Conflict(
                "non-genesis RealmCommit has no stream predecessor".into(),
            )
            .into());
        }
    }

    sql_query(
        "INSERT INTO realm_commits \
         (commit_id, realm_id, stream_key, stream_ref, stream_position, previous_commit_ref, event_pk, governance_generation, commit_json, committed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind::<Text, _>(transaction.commit.commit_id.as_str())
    .bind::<Text, _>(transaction.commit.realm_id.as_str())
    .bind::<Text, _>(&stream_key)
    .bind::<Jsonb, _>(serde_json::to_value(&transaction.commit.stream_ref).map_err(PersistenceError::database)?)
    .bind::<BigInt, _>(stream_position)
    .bind::<Nullable<Text>, _>(transaction.commit.previous_commit_ref.as_ref().map(|id| id.as_str()))
    .bind::<BigInt, _>(event_row.event_pk)
    .bind::<BigInt, _>(governance_generation)
    .bind::<Jsonb, _>(&commit_json)
    .bind::<Timestamptz, _>(transaction.commit.committed_at)
    .execute(&mut *conn)
    .await?;
    sql_query(
        "UPDATE canonical_events SET state = 'committed', committed_at = $2, rejection_reason = NULL \
         WHERE pk = $1 AND state = 'queued'",
    )
    .bind::<BigInt, _>(event_row.event_pk)
    .bind::<Timestamptz, _>(transaction.commit.committed_at)
    .execute(&mut *conn)
    .await?;

    crate::agent_origin::accept_staged_control_source_in_connection(
        conn,
        &transaction.event,
        &transaction.commit,
    )
    .await?;

    crate::realm_lifecycle_current_results::commit_in_connection(
        conn,
        &transaction.event,
        &transaction.commit,
    )
    .await?;

    Ok(AuthorityCommitWriteOutcome::Committed)
}

#[cfg(any(test, feature = "test-support"))]
fn require_atomic_admission_outcome(
    outcome: AuthorityCommitWriteOutcome,
) -> Result<AuthorityCommitWriteOutcome, PgTransactionError> {
    match outcome {
        AuthorityCommitWriteOutcome::Committed => Ok(AuthorityCommitWriteOutcome::Committed),
        AuthorityCommitWriteOutcome::Duplicate => Ok(AuthorityCommitWriteOutcome::Duplicate),
        AuthorityCommitWriteOutcome::StaleAuthority(_) => Err(PersistenceError::Conflict(
            "stale Realm authority during atomic Event admission".into(),
        )
        .into()),
    }
}

#[derive(QueryableByName)]
struct ProducerCurrentValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(QueryableByName)]
struct ProducerAuthorizationRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

pub(crate) async fn check_self_producer_guard_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    guard: &SelfProducerCommitGuard,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if let SelfProducerCommitGuard::MimiFacade { .. } = guard {
        return crate::mimi_admission::check_facade_producer_in_connection(
            conn,
            event,
            guard,
            committed_at,
        )
        .await;
    }
    let actor = event.actor_id.as_account_id().ok_or_else(|| {
        PersistenceError::Conflict("self Event producer is not an account".to_owned())
    })?;
    let method = &event
        .producer_proof
        .as_ref()
        .ok_or_else(|| {
            PersistenceError::Conflict("self Event producer proof is missing".to_owned())
        })?
        .verification_method;
    if event.executed_by.is_some() {
        return Err(PersistenceError::Conflict(
            "self Event cannot delegate its producer".to_owned(),
        ));
    }
    match guard {
        SelfProducerCommitGuard::MimiFacade { .. } => unreachable!("MIMI guard dispatched above"),
        SelfProducerCommitGuard::HumanDevice(selector)
        | SelfProducerCommitGuard::HumanDeviceEvidence { selector, .. } => {
            if selector.principal_id != actor.principal_id
                || selector.station_id != actor.station_id
                || !method
                    .as_str()
                    .ends_with(&format!("#{}", selector.device_id))
            {
                return Err(PersistenceError::Conflict(
                    "self Event device guard differs from producer".to_owned(),
                ));
            }
            crate::ensure_gate_allowed_in_transaction(conn, selector).await
        }
        SelfProducerCommitGuard::Agent {
            pcr_realm_id,
            agent_id,
            authorization_ref,
            verification_method,
        } => {
            if agent_id != &actor.principal_id || verification_method != method {
                return Err(PersistenceError::Conflict(
                    "self Event Agent guard differs from producer".to_owned(),
                ));
            }
            // encryption-and-audit.md §2.5.2: an Agent runtime whose authorize
            // is revoked, replaced or expired at this cut is refused with the
            // universal `capability_denied`.
            check_agent_endpoint_current_in_connection(
                conn,
                pcr_realm_id,
                agent_id,
                authorization_ref,
                verification_method,
                committed_at,
            )
            .await
            .map_err(|error| match error {
                PersistenceError::Conflict(detail)
                    if coland_storage::ConflictCode::from_detail(&detail).is_none() =>
                {
                    PersistenceError::Conflict(format!(
                        "{}: {detail}",
                        coland_storage::ConflictCode::CapabilityDenied
                    ))
                }
                other => other,
            })
        }
    }
}

/// Recheck, inside the caller's transaction, that `authorization_ref` is the
/// Agent's committed `ak.agent.key_authorize` and still its single active
/// current key for `verification_method` at `committed_at`, with the Agent
/// active.
/// Shared by Agent-produced Events and Agent-sent DeviceMessages.
pub(crate) async fn check_agent_endpoint_current_in_connection(
    conn: &mut AsyncPgConnection,
    pcr_realm_id: &arkret_wire::RealmId,
    agent_id: &arkret_wire::DidCoreId,
    authorization_ref: &arkret_wire::CommittedEventRef,
    verification_method: &arkret_wire::DidUrl,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let method = verification_method;
    if authorization_ref.stream_ref.realm_id() != pcr_realm_id {
        return Err(PersistenceError::Conflict(
            "Agent guard authorization is outside its PCR Realm".to_owned(),
        ));
    }
    let authorization = sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.state='committed'",
    )
    .bind::<Binary, _>(
        ids::parse_event_id(authorization_ref.event_id.as_str())
            .ok_or_else(|| invalid("Agent authorization Event id is invalid"))?
            .to_vec(),
    )
    .get_result::<ProducerAuthorizationRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| {
        PersistenceError::Conflict("Agent authorization Event is not committed".to_owned())
    })?;
    let source_event: arkret_wire::Event =
        decode_json(authorization.envelope, "Agent authorization Event")?;
    let source_commit: arkret_wire::RealmCommit =
        decode_json(authorization.commit_json, "Agent authorization Commit")?;
    if source_event.kind != arkret_wire::EventKind::AgentKeyAuthorize
        || source_event.event_id != authorization_ref.event_id
        || source_event.realm_id != *pcr_realm_id
        || source_commit.event_ref != authorization_ref.event_id
        || source_commit.commit_id != authorization_ref.commit_id
        || source_commit.stream_ref != authorization_ref.stream_ref
        || source_commit.stream_position != authorization_ref.stream_position
    {
        return Err(PersistenceError::Conflict(
            "Agent authorization Commit differs from guarded source".to_owned(),
        ));
    }
    lock_agent_producer_current(conn, pcr_realm_id, agent_id).await?;
    let status = sql_query("SELECT value FROM agent_status_current_results WHERE realm_id=$1 AND agent_id=$2 FOR SHARE")
        .bind::<Text, _>(pcr_realm_id.as_str())
        .bind::<Text, _>(agent_id.as_str())
        .get_result::<ProducerCurrentValueRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
    if status.as_ref().and_then(|row| row.value.as_str()) != Some("active") {
        return Err(PersistenceError::Conflict(
            "Agent producer is no longer active".to_owned(),
        ));
    }
    let rows = sql_query(
        "SELECT value FROM agent_key_current_results WHERE realm_id=$1 AND agent_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(pcr_realm_id.as_str())
    .bind::<Text, _>(agent_id.as_str())
    .load::<ProducerCurrentValueRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut active = Vec::new();
    for row in rows {
        let entries = row
            .value
            .get("authorizations")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "stored Agent key current result has no authorizations".to_owned(),
                )
            })?;
        for entry in entries {
            let Some(raw_method) = entry
                .pointer("/value/verification_method")
                .and_then(Value::as_str)
            else {
                continue;
            };
            let payload: arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload =
                serde_json::from_value(entry.get("value").cloned().unwrap_or(Value::Null))
                .map_err(|error| PersistenceError::Internal(format!("stored Agent key authorization invalid: {error}")))?;
            if payload
                .expires_at
                .is_some_and(|expiry| expiry <= committed_at)
            {
                continue;
            }
            if payload.agent_id != *agent_id
                || entry.get("value")
                    != Some(
                        &serde_json::to_value(&source_event.payload)
                            .map_err(PersistenceError::database)?,
                    )
            {
                return Err(PersistenceError::Conflict(
                    "Agent current authorization differs from its accepted Event".to_owned(),
                ));
            }
            let tag = entry.get("tag_id").and_then(Value::as_str).ok_or_else(|| {
                PersistenceError::Internal("stored Agent authorization has no tag id".to_owned())
            })?;
            active.push((tag.to_owned(), raw_method.to_owned()));
        }
    }
    if active.len() != 1
        || active[0].0 != format!("{}:1", authorization_ref.event_id)
        || active[0].1 != method.as_str()
    {
        return Err(PersistenceError::Conflict(
            "Agent producer authorization changed before commit".to_owned(),
        ));
    }
    Ok(())
}

impl PgAuthorityCommitStore {
    async fn admit_ordinary_realm_bootstrap_unit_inner(
        &self,
        unit: &OrdinaryRealmBootstrapCommitUnit,
        producer_guards: Option<&[SelfProducerCommitGuard]>,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<OrdinaryRealmBootstrapCommitOutcome> {
        unit.validate().map_err(invalid)?;
        if unit.event_approvals.is_empty()
            && unit
                .submission
                .events
                .iter()
                .any(|item| item.approval_signatures.is_some())
        {
            return Err(invalid(
                "ordinary Realm bootstrap approval history is incomplete",
            ));
        }
        if producer_guards.is_some_and(|guards| guards.len() != unit.transactions.len()) {
            return Err(invalid(
                "ordinary Realm bootstrap needs one producer guard per Event",
            ));
        }
        let first = &unit.transactions[0];
        let authority = &first.expected_authority;
        if authority.generation != 0
            || authority.last_handoff_ref.is_some()
            || authority.authority_ref
                != arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    first.event.event_id.clone(),
                )
        {
            return Err(invalid(
                "ordinary Realm bootstrap requires its exact genesis authority",
            ));
        }
        let realm_id = authority.realm_id.as_str().to_owned();
        let key = unit.submission.idempotency_key.as_uuid().to_string();
        let commits = unit
            .transactions
            .iter()
            .map(|transaction| transaction.commit.clone())
            .collect::<Vec<_>>();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let inserted = sql_query(
                "INSERT INTO ordinary_realm_bootstrap_units \
                 (realm_id,idempotency_key,exact_request_body,commits_json,committed_at) \
                 VALUES ($1,$2,$3,'[]'::jsonb,$4) ON CONFLICT DO NOTHING",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Text, _>(&key)
            .bind::<Binary, _>(&unit.exact_request_body)
            .bind::<Timestamptz, _>(queued_at)
            .execute(&mut *conn)
            .await?;
            if inserted == 0 {
                let existing = sql_query(
                    "SELECT idempotency_key,exact_request_body,commits_json \
                     FROM ordinary_realm_bootstrap_units WHERE realm_id=$1 FOR UPDATE",
                )
                .bind::<Text, _>(&realm_id)
                .get_result::<OrdinaryBootstrapUnitRow>(&mut *conn)
                .await
                .optional()?;
                let Some(existing) = existing else {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()).into());
                };
                if existing.idempotency_key != key
                    || existing.exact_request_body != unit.exact_request_body
                {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()).into());
                }
                let stored = decode_json::<Vec<arkret_wire::RealmCommit>>(
                    existing.commits_json,
                    "ordinary Realm bootstrap committed unit",
                )?;
                if stored.len() != commits.len() || stored.is_empty() {
                    return Err(PersistenceError::Internal(
                        "stored ordinary Realm bootstrap unit is incomplete".to_owned(),
                    )
                    .into());
                }
                return Ok(OrdinaryRealmBootstrapCommitOutcome::Duplicate(stored));
            }
            let authority_inserted = sql_query(
                "INSERT INTO realm_authorities \
                 (realm_id,generation,service_id,authority_ref,last_handoff_ref) \
                 VALUES ($1,0,$2,$3,NULL) ON CONFLICT (realm_id) DO NOTHING",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Text, _>(authority.service_id.as_str())
            .bind::<Jsonb, _>(
                serde_json::to_value(&authority.authority_ref)
                    .map_err(PersistenceError::database)?,
            )
            .execute(&mut *conn)
            .await?;
            if authority_inserted != 1 {
                return Err(PersistenceError::Conflict("realm_already_exists".to_owned()).into());
            }
            let mut approval_consumption = crate::approval_admission::BootstrapApprovalConsumption::default();
            for (index, transaction) in unit.transactions.iter().enumerate() {
                let approvals = crate::approval_admission::validate_bootstrap_candidate(unit, index)?;
                if let Some(guards) = producer_guards {
                    check_self_producer_guard_in_connection(
                        conn,
                        &transaction.event,
                        &guards[index],
                        transaction.commit.committed_at,
                    )
                    .await?;
                }
                let prepared_human = crate::agent_producer_signer_keys::validate_prepared_local_human_in_connection(conn, transaction).await?;
                queue_event_in_connection(conn, &transaction.event, queued_at).await?;
                match commit_transaction_in_connection(conn, transaction).await? {
                    AuthorityCommitWriteOutcome::Committed => {}
                    AuthorityCommitWriteOutcome::Duplicate => {
                        return Err(
                            PersistenceError::Conflict("duplicate_conflict".to_owned()).into()
                        );
                    }
                    AuthorityCommitWriteOutcome::StaleAuthority(_) => {
                        return Err(
                            PersistenceError::Conflict("stale_realm_authority".to_owned()).into(),
                        );
                    }
                }
                if let Some(fact) = prepared_human.as_ref() {
                    crate::agent_producer_signer_keys::retain_prepared_human_in_connection(conn, &transaction.event, &transaction.commit, fact).await?;
                    crate::account_device_committed_evidence::retain_from_guard(conn, &transaction.event, &transaction.commit, fact, producer_guards.map(|guards| &guards[index])).await?;
                } else if let Some(guards) = producer_guards {
                    crate::agent_producer_signer_keys::retain_in_connection(
                        conn, &transaction.event, &transaction.commit, Some(&guards[index]),
                    ).await?;
                }
                commit_realm_authority_root_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
                crate::realm_bootstrap_current_results::commit_ordinary_bootstrap_singleton_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
                crate::unit_of_work::commit_parent_membership_current_results(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
                commit_capability_grant_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
                commit_mimi_room_binding_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
                // This closed founding unit has no pre-existing Realm grants
                // or governance Policy. Evidence is still verified and its
                // nonce consumed at the successful target's accepting cut.
                let approved = approval_consumption.qualify(approvals)?;
                crate::approval_admission::consume_and_audit(conn, &transaction.event, &transaction.commit,
                    &approved, &serde_json::json!({"unit_kind":"ordinary_realm_bootstrap","idempotency_key":key,
                        "commits":unit.transactions.iter().map(|transaction| &transaction.commit).collect::<Vec<_>>()})).await?;
            }
            crate::account_summary::publish_realm_account_summary_in_connection(
                conn,
                &authority.realm_id,
            )
            .await?;
            sql_query(
                "UPDATE ordinary_realm_bootstrap_units SET commits_json=$2 WHERE realm_id=$1",
            )
            .bind::<Text, _>(&realm_id)
            .bind::<Jsonb, _>(serde_json::to_value(&commits).map_err(PersistenceError::database)?)
            .execute(&mut *conn)
            .await?;
            Ok(OrdinaryRealmBootstrapCommitOutcome::Committed(commits))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

/// Whether `member` is a current joined member of `realm_id` in this
/// Station's accepted state (see
/// [`AuthorityCommitStore::accepted_current_member_joined`]).
pub(crate) async fn accepted_current_member_joined_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
) -> PersistenceResult<bool> {
    let row = sql_query(
        // A row is backed by the Realm-stream Commit that installed it,
        // held here, or -- on a member Station -- by the verified
        // bootstrap snapshot the held replica is anchored on, whose rows
        // name Commits below the replica's floor (decision 0116).
        "SELECT EXISTS (\
            SELECT 1 FROM member_state_current_results m \
            WHERE m.realm_id = $1 AND m.member_id = $2 AND m.membership = 'join' \
              AND (EXISTS (SELECT 1 FROM realm_commits c \
                           WHERE c.commit_id = m.current_commit_id \
                             AND c.realm_id = m.realm_id \
                             AND c.stream_position = m.current_stream_position \
                             AND c.stream_ref->>'kind' = 'realm' \
                             AND c.stream_ref->>'realm_id' = m.realm_id) \
                   OR EXISTS (SELECT 1 FROM replica_stream_anchors a \
                              WHERE a.realm_id = m.realm_id \
                                AND a.stream_key=$3 \
                                AND a.anchor_stream_position >= m.current_stream_position))\
         ) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .bind::<Text, _>(stream_key(&arkret_wire::CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    })?)
    .get_result::<PresenceRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(row.present)
}

/// Whether this Station's accepted parent Realm `member_state` current of
/// `member` is `join` at exactly `bound` (`circle.md` section 9.1), the
/// revision a Circle join signed. A local Realm replica that has not reached
/// `bound` on the Realm stream, or already holds another revision, answers
/// `false`; the comparison never uses a Circle-stream position.
pub(crate) async fn parent_join_at_revision_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
    bound: &arkret_wire::CurrentRevision,
) -> PersistenceResult<bool> {
    let row = sql_query(
        "SELECT EXISTS (\
            SELECT 1 FROM member_state_current_results m \
            WHERE m.realm_id = $1 AND m.member_id = $2 AND m.membership = 'join' \
              AND m.current_commit_id = $4 AND m.current_stream_position = $5 \
              AND (EXISTS (SELECT 1 FROM realm_commits c \
                           WHERE c.commit_id = m.current_commit_id \
                             AND c.realm_id = m.realm_id \
                             AND c.stream_position = m.current_stream_position \
                             AND c.stream_ref->>'kind' = 'realm' \
                             AND c.stream_ref->>'realm_id' = m.realm_id) \
                   OR EXISTS (SELECT 1 FROM replica_stream_anchors a \
                              WHERE a.realm_id = m.realm_id \
                                AND a.stream_key=$3 \
                                AND a.anchor_stream_position >= m.current_stream_position))\
         ) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .bind::<Text, _>(stream_key(&arkret_wire::CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    })?)
    .bind::<Text, _>(bound.commit_id.as_str())
    .bind::<BigInt, _>(i64::try_from(bound.stream_position).map_err(PersistenceError::database)?)
    .get_result::<PresenceRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(row.present)
}

#[derive(QueryableByName)]
struct RosterControllerRow {
    #[diesel(sql_type = Jsonb)]
    controller_actor_id: Value,
}

#[derive(QueryableByName)]
struct RosterMemberRow {
    #[diesel(sql_type = Text)]
    member_id: String,
}

/// See [`AuthorityCommitStore::accepted_realm_roster`]. The governing Station
/// (and a founding peer) holds the root as its own typed current row; a member
/// Station holds the governing Station's verified root row.
async fn accepted_realm_roster_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<coland_storage::AcceptedRealmRoster>> {
    let Some(controller) = sql_query(
        "SELECT controller_actor_id FROM realm_authority_root_current_results WHERE realm_id = $1 \
         UNION ALL \
         SELECT value->'controller_actor_id' AS controller_actor_id FROM replica_authorization_rows \
          WHERE realm_id = $1 AND selector->>'kind' = 'realm_authority_root' \
         LIMIT 1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<RosterControllerRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    else {
        return Ok(None);
    };
    let controller_actor_id: arkret_wire::ActorId =
        serde_json::from_value(controller.controller_actor_id).map_err(|error| {
            PersistenceError::Internal(format!("stored Realm root controller is invalid: {error}"))
        })?;
    let rows = sql_query(
        // The same backing rule as `accepted_current_member_joined_in_connection`.
        "SELECT m.member_id FROM member_state_current_results m \
          WHERE m.realm_id = $1 AND m.membership = 'join' \
            AND (EXISTS (SELECT 1 FROM realm_commits c \
                         WHERE c.commit_id = m.current_commit_id \
                           AND c.realm_id = m.realm_id \
                           AND c.stream_position = m.current_stream_position \
                           AND c.stream_ref->>'kind' = 'realm' \
                           AND c.stream_ref->>'realm_id' = m.realm_id) \
                 OR EXISTS (SELECT 1 FROM replica_stream_anchors a \
                            WHERE a.realm_id = m.realm_id \
                              AND a.stream_key = $2 \
                              AND a.anchor_stream_position >= m.current_stream_position)) \
          ORDER BY m.member_id",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(stream_key(&arkret_wire::CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    })?)
    .load::<RosterMemberRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let joined_members = rows
        .into_iter()
        .map(|row| {
            serde_json::from_str::<arkret_wire::ActorId>(&row.member_id).map_err(|error| {
                PersistenceError::Internal(format!("stored Realm member is invalid: {error}"))
            })
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    Ok(Some(coland_storage::AcceptedRealmRoster {
        controller_actor_id,
        joined_members,
    }))
}

#[async_trait]
impl AuthorityCommitStore for PgAuthorityCommitStore {
    async fn ordinary_realm_bootstrap_replay(
        &self,
        submission: &arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitSubmission,
        exact_request_body: &[u8],
    ) -> PersistenceResult<Option<Vec<arkret_wire::RealmCommit>>> {
        submission.validate().map_err(invalid)?;
        match serde_json::from_slice::<arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest>(exact_request_body) {
            Ok(arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(parsed)) if parsed == *submission => {},
            _ => return Err(invalid("ordinary Realm bootstrap exact body differs")),
        }
        let mut conn = pg_conn(&self.pool).await?;
        let existing = sql_query("SELECT idempotency_key,exact_request_body,commits_json FROM ordinary_realm_bootstrap_units WHERE realm_id=$1 OR idempotency_key=$2")
            .bind::<Text,_>(submission.events[0].event.realm_id.as_str())
            .bind::<Text,_>(submission.idempotency_key.as_uuid().to_string())
            .load::<OrdinaryBootstrapUnitRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        if existing.is_empty() {
            return Ok(None);
        }
        if existing.len() != 1
            || existing[0].idempotency_key != submission.idempotency_key.as_uuid().to_string()
            || existing[0].exact_request_body != exact_request_body
        {
            return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
        }
        let commits: Vec<arkret_wire::RealmCommit> = decode_json(
            existing[0].commits_json.clone(),
            "ordinary bootstrap exact replay",
        )?;
        if commits.len() != submission.events.len()
            || commits
                .iter()
                .zip(&submission.events)
                .any(|(commit, item)| {
                    commit.event_ref != item.event.event_id
                        || commit.realm_id != item.event.realm_id
                })
        {
            return Err(PersistenceError::Internal(
                "stored ordinary bootstrap outcome differs from its exact unit".to_owned(),
            ));
        }
        arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapAcceptanceOutcome {
            unit_kind: submission.unit_kind,
            status:
                arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Duplicate,
            commits: commits.clone(),
        }
        .validate()
        .map_err(invalid)?;
        Ok(Some(commits))
    }

    async fn owned_agent_authorization_check(
        &self,
        caller: &arkret_wire::ActorId,
        station: &arkret_wire::DidCoreId,
        request: &arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::governance::authorization::AuthzCheckOutcome>,
    > {
        let Some(realm) = request
            .resource
            .as_ref()
            .and_then(|resource| resource.realm_id.as_ref())
        else {
            return Ok(None);
        };
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            let Some(account) = request.actor_id.as_account_id() else { return Ok(None) };
            if !crate::committed_disclosure::ordinary_agent_read_ceiling(crate::account_stream_scan::realm_purpose(conn, realm).await?)
                || !crate::realm_authorization_cut::is_owned_agent_in_connection(conn, realm, account).await? {
                return Ok(None);
            }
            crate::realm_authorization_cut::lock_realm_authorization_cut(conn, realm).await?;
            let authority = sql_query("SELECT realm_id,generation,service_id,authority_ref,last_handoff_ref FROM realm_authorities WHERE realm_id=$1")
                .bind::<Text,_>(realm.as_str()).get_result::<AuthorityRow>(&mut *conn).await?;
            if authority.service_id != station.as_str() {
                return Err(PersistenceError::Conflict("revision_unavailable: current governing authorization is unavailable".into()).into());
            }
            crate::realm_authorization_cut::owned_agent_authorization_check_in_connection(conn, caller, request).await.map_err(Into::into)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn acquire_committed_content_delivery(
        &self,
        account: &arkret_wire::AccountId,
        station: &arkret_wire::DidCoreId,
        input: &coland_storage::AccountContentDeliveryInput,
    ) -> PersistenceResult<Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>> {
        crate::account_content_delivery::acquire(&self.pool, account, station, input).await
    }

    async fn acquire_native_message_reply_preparation(
        &self,
        request: coland_storage::NativeMessageReplyPreparation<'_>,
    ) -> PersistenceResult<Box<dyn coland_storage::AccountContentDeliveryGuard>> {
        crate::account_content_delivery::acquire_native_message_reply_preparation(
            &self.pool, request,
        )
        .await
    }

    async fn stage_agent_control_source(
        &self,
        full: &arkret_wire::CommittedEventFullView,
        dependency: &arkret_models_identity::AgentSignerDependency,
        history: &arkret_models_identity::AuthenticatedServiceResolution,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::agent_origin::stage_control_source_in_connection(conn, full, dependency, history)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn prepare_agent_origin_state(
        &self,
        event: &arkret_wire::Event,
        _at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<arkret_models_identity::AgentAuthorityState> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::agent_origin::assemble_state_in_connection(conn, event)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn agent_origin_controller_gate_request(
        &self,
        event: &arkret_wire::Event,
        state: &arkret_models_identity::AgentAuthorityState,
    ) -> PersistenceResult<arkret_wire::RequestId> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::agent_origin::gate_request_in_connection(conn, event, state)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn retain_agent_forward_evidence_at_same_cut(
        &self,
        event: &arkret_wire::Event,
        evidence: &arkret_models_identity::AgentProducerEvidence,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::agent_origin::retain_in_connection(conn, event, evidence, at)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn human_signer_fact(
        &self,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact>,
    > {
        let mut conn = pg_conn(&self.pool).await?;
        crate::agent_producer_signer_keys::human_source_for_commit_in_connection(
            &mut conn, event, commit,
        )
        .await
    }

    async fn producer_signer_fact(
        &self,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>,
    > {
        let mut conn = pg_conn(&self.pool).await?;
        crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
            &mut conn, event, commit,
        )
        .await
    }
    async fn prepare_service_signer_fact(
        &self,
        event: &arkret_wire::Event,
        guard: &coland_storage::AppletEventProducerGuard,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<arkret_models_collaboration::authority_commit::ServiceHistoricalSignerFact>
    {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::managed_message_actor::require_applet_producer_in_connection(
                conn, event, guard, at,
            )
            .await
            .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn prepare_human_signer_fact(
        &self,
        event: &arkret_wire::Event,
        admitted_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact>,
    > {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::agent_producer_signer_keys::prepare_local_human_source_in_connection(
                conn,
                event,
                admitted_at,
            )
            .await
            .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn historical_self_pcr_producer_signer_key(
        &self,
        realm_id: &arkret_wire::RealmId,
        selector: &arkret_models_identity::SignerKeyQuerySelector,
        recipient: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<arkret_models_identity::SignerKeyQueryOutcome>> {
        crate::agent_producer_signer_keys::read_self_pcr(&self.pool, realm_id, selector, recipient)
            .await
    }

    async fn historical_producer_signer_key(
        &self,
        realm_id: &arkret_wire::RealmId,
        selector: &arkret_models_identity::SignerKeyQuerySelector,
    ) -> PersistenceResult<Option<arkret_models_identity::SignerKeyQueryOutcome>> {
        crate::agent_producer_signer_keys::read(&self.pool, realm_id, selector).await
    }

    async fn mls_member_roster_selector(
        &self,
        request: &arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<coland_storage::MlsMemberRosterSelectorRead> {
        crate::mls_roster_authority_read::member_selector(&self.pool, request, issuer).await
    }

    async fn mls_roster_authority_read(
        &self,
        request: &arkret_models_collaboration::mls_roster_authority::MlsRosterAuthorityReadRequestBody,
        issuer: &arkret_wire::DidCoreId,
        source_peer: Option<&arkret_wire::DidCoreId>,
    ) -> PersistenceResult<coland_storage::MlsRosterAuthorityRead> {
        crate::mls_roster_authority_read::read(&self.pool, request, issuer, source_peer).await
    }

    async fn install_mls_add_authority_attestation(
        &self,
        verified: &coland_storage::VerifiedMlsAddAuthorityAttestation,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<arkret_models_collaboration::mls_roster_authority::MlsAttestAddOutcome>
    {
        crate::mls_roster_attest_add::install(&self.pool, verified, issuer).await
    }

    async fn mls_recipient_attestation(
        &self,
        commit: &arkret_wire::EventId,
        welcome: &arkret_wire::MlsWelcomeDeliveryId,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody>,
    > {
        crate::mls_recipient_attestation_outbox::get(&self.pool, commit, welcome).await
    }

    async fn pending_mls_recipient_attestations(
        &self,
        limit: usize,
    ) -> PersistenceResult<
        Vec<arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody>,
    > {
        crate::mls_recipient_attestation_outbox::pending(&self.pool, limit).await
    }

    async fn acknowledge_mls_recipient_attestation(
        &self,
        request: &arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody,
        digest: &arkret_wire::Hash,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        crate::mls_recipient_attestation_outbox::acknowledge(&self.pool, request, digest, at).await
    }

    async fn mls_member_group_state_material_read(
        &self,
        request: &arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody,
        issuer: &arkret_wire::DidCoreId,
        source_peer: Option<&arkret_wire::DidCoreId>,
    ) -> PersistenceResult<coland_storage::MlsMemberGroupStateMaterialRead> {
        crate::mls_group_state_material_read::read(&self.pool, request, issuer, source_peer).await
    }

    async fn admit_accepted_device_authorization(
        &self,
        transaction: &AuthorityCommitTransaction,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<AcceptedDeviceAuthorizationOutcome> {
        transaction.validate().map_err(invalid)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::pcr_accepted_device_unit::admit_accepted_device_unit_in_connection(
                conn,
                transaction,
                queued_at,
            )
            .await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn pcr_genesis_replay(
        &self,
        submission: &arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
        exact_request_body: &[u8],
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::principal_operations::PcrGenesisAdmissionOutcome>,
    > {
        use arkret_models_collaboration::principal_operations::PcrGenesisAdmissionOutcome;

        let mut conn = pg_conn(&self.pool).await?;
        let key = submission.idempotency_key.to_string();
        let existing = sql_query(
            "SELECT realm_id,idempotency_key,exact_request_body,result_json \
             FROM pcr_genesis_units WHERE realm_id=$1 OR idempotency_key=$2 \
             ORDER BY (realm_id=$1) DESC LIMIT 1",
        )
        .bind::<Text, _>(submission.pcr_realm_id.as_str())
        .bind::<Text, _>(&key)
        .get_result::<PcrGenesisUnitRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        let Some(existing) = existing else {
            return Ok(None);
        };
        if existing.realm_id != submission.pcr_realm_id.as_str()
            || existing.idempotency_key != key
            || existing.exact_request_body != exact_request_body
        {
            return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()));
        }
        let stored: PcrGenesisAdmissionOutcome =
            decode_json(existing.result_json, "PCR genesis result")?;
        stored.validate_against(submission).map_err(invalid)?;
        Ok(Some(stored))
    }

    async fn admit_pcr_genesis_unit(
        &self,
        unit: &PcrGenesisCommitUnit,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<PcrGenesisCommitOutcome> {
        use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
        use arkret_models_collaboration::principal_operations::PcrGenesisAdmissionOutcome;

        unit.validate().map_err(invalid)?;
        let submission = &unit.submission;
        let authority = &unit.transactions[0].expected_authority;
        let realm_id = submission.pcr_realm_id.as_str();
        let key = submission.idempotency_key.to_string();
        let authorize_payload: DeviceAuthorizePayload = serde_json::from_value(Value::Object(
            unit.transactions[1]
                .event
                .payload
                .clone()
                .into_iter()
                .collect(),
        ))
        .map_err(|error| invalid(format!("founding device payload is invalid: {error}")))?;
        let commits = unit
            .transactions
            .clone()
            .map(|transaction| transaction.commit);
        let result = PcrGenesisAdmissionOutcome {
            principal_id: submission.principal_id.clone(),
            pcr_realm_id: submission.pcr_realm_id.clone(),
            accepted_device_id: authorize_payload.device_id.clone(),
            resolution: arkret_models_identity::PrincipalResolutionProjection {
                did: submission.did.clone(),
                method_history_head: submission
                    .registration_did_evidence
                    .method_history_head
                    .clone(),
                version_id: submission.did_version_id.clone(),
                resolution_event_ref: unit.transactions[0].event.event_id.to_string(),
                updated_at: commits[0].committed_at,
            },
            commits,
        };
        result.validate_against(submission).map_err(invalid)?;
        let result_json = serde_json::to_value(&result).map_err(PersistenceError::database)?;
        let commits_json =
            serde_json::to_value(&result.commits).map_err(PersistenceError::database)?;
        let resolution_json =
            serde_json::to_value(&result.resolution).map_err(PersistenceError::database)?;
        let create_json = serde_json::to_value(&unit.transactions[0].event)
            .map_err(PersistenceError::database)?;
        let authorization_ref = arkret_wire::CommittedEventRef {
            event_id: unit.transactions[1].event.event_id.clone(),
            commit_id: result.commits[1].commit_id.clone(),
            stream_ref: result.commits[1].stream_ref.clone(),
            stream_position: result.commits[1].stream_position,
        };
        let mut device_json =
            serde_json::to_value(&authorize_payload).map_err(PersistenceError::database)?;
        let device_fields = device_json
            .as_object_mut()
            .ok_or_else(|| invalid("founding device payload must be a JSON object"))?;
        device_fields.insert(
            "device_authorization_ref".to_owned(),
            serde_json::to_value(&authorization_ref).map_err(PersistenceError::database)?,
        );
        device_fields.insert(
            "device_authorize_event_id".to_owned(),
            serde_json::to_value(&unit.transactions[1].event.event_id)
                .map_err(PersistenceError::database)?,
        );
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let inserted = sql_query(
                "INSERT INTO pcr_genesis_units \
                 (realm_id,principal_id,station_id,idempotency_key,exact_request_body,commits_json,\
                  result_json,committed_at) \
                 VALUES ($1,$2,$3,$4,$5,'[]'::jsonb,'{}'::jsonb,$6) ON CONFLICT DO NOTHING",
            )
            .bind::<Text, _>(realm_id)
            .bind::<Text, _>(submission.principal_id.as_str())
            .bind::<Text, _>(submission.account_authority_id.as_str())
            .bind::<Text, _>(&key)
            .bind::<Binary, _>(&unit.exact_request_body)
            .bind::<Timestamptz, _>(queued_at)
            .execute(&mut *conn)
            .await?;
            if inserted == 0 {
                let existing = sql_query(
                    "SELECT realm_id,idempotency_key,exact_request_body,result_json \
                     FROM pcr_genesis_units WHERE realm_id=$1 OR idempotency_key=$2 \
                     ORDER BY (realm_id=$1) DESC LIMIT 1 FOR UPDATE",
                )
                .bind::<Text, _>(realm_id)
                .bind::<Text, _>(&key)
                .get_result::<PcrGenesisUnitRow>(&mut *conn)
                .await
                .optional()?;
                let Some(existing) = existing else {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()).into());
                };
                if existing.realm_id != realm_id || existing.idempotency_key != key || existing.exact_request_body != unit.exact_request_body {
                    return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()).into());
                }
                let stored: PcrGenesisAdmissionOutcome = decode_json(existing.result_json, "PCR genesis result")?;
                stored.validate_against(submission).map_err(invalid)?;
                return Ok(PcrGenesisCommitOutcome::Duplicate(stored));
            }
            let authority_inserted = sql_query(
                "INSERT INTO realm_authorities \
                 (realm_id,generation,service_id,authority_ref,last_handoff_ref) \
                 VALUES ($1,0,$2,$3,NULL) ON CONFLICT (realm_id) DO NOTHING",
            )
            .bind::<Text, _>(realm_id)
            .bind::<Text, _>(authority.service_id.as_str())
            .bind::<Jsonb, _>(serde_json::to_value(&authority.authority_ref).map_err(PersistenceError::database)?)
            .execute(&mut *conn)
            .await?;
            if authority_inserted != 1 {
                return Err(PersistenceError::Conflict("realm_already_exists".to_owned()).into());
            }
            for transaction in &unit.transactions {
                queue_event_in_connection(conn, &transaction.event, queued_at).await?;
                match commit_verified_pcr_device_transaction_in_connection(conn, transaction).await? {
                    AuthorityCommitWriteOutcome::Committed => {}
                    AuthorityCommitWriteOutcome::Duplicate => {
                        return Err(PersistenceError::Conflict("duplicate_conflict".to_owned()).into());
                    }
                    AuthorityCommitWriteOutcome::StaleAuthority(_) => {
                        return Err(PersistenceError::Conflict("stale_realm_authority".to_owned()).into());
                    }
                }
                commit_realm_authority_root_current_result_in_connection(conn, &transaction.event, &transaction.commit).await?;
                commit_capability_grant_current_result_in_connection(conn, &transaction.event, &transaction.commit).await?;
                crate::pcr_device_current_results::project_pcr_device_current_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                    Some(&arkret_wire::AccountId::new(
                        submission.principal_id.clone(),
                        submission.account_authority_id.clone(),
                    )),
                )
                .await?;
            }
            let resolution_inserted = sql_query(
                "WITH inserted AS ( \
                   INSERT INTO principal_resolutions \
                     (principal_id,station_id,pcr_realm_id,genesis_event_id,current_event_id,projection,updated_at) \
                   VALUES ($1,$2,$3,$4,$4,$5,$6) ON CONFLICT DO NOTHING \
                   RETURNING principal_id,station_id \
                 ), inserted_event AS ( \
                   INSERT INTO principal_resolution_events \
                     (principal_id,station_id,event_id,previous_event_id,method_history_head,event_json,created_at) \
                   SELECT principal_id,station_id,$4,NULL,$7,$8,$6 FROM inserted \
                 ) SELECT EXISTS(SELECT 1 FROM inserted) AS present",
            )
            .bind::<Text, _>(submission.principal_id.as_str())
            .bind::<Text, _>(submission.account_authority_id.as_str())
            .bind::<Text, _>(realm_id)
            .bind::<Text, _>(unit.transactions[0].event.event_id.as_str())
            .bind::<Jsonb, _>(&resolution_json)
            .bind::<Timestamptz, _>(result.resolution.updated_at)
            .bind::<Text, _>(&result.resolution.method_history_head)
            .bind::<Jsonb, _>(&create_json)
            .get_result::<PresenceRow>(&mut *conn)
            .await?;
            if !resolution_inserted.present {
                return Err(PersistenceError::Conflict("principal_resolution_already_exists".to_owned()).into());
            }
            let device_inserted = sql_query(
                "INSERT INTO devices \
                 (id,station_id,actor_id,device_id,device_key,verification_state,payload,created_at,updated_at) \
                 VALUES ($1,$2,$3,$4,$5,'verified',$6,$7,$7) \
                 ON CONFLICT(actor_id,device_id) DO NOTHING",
            )
            .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
            .bind::<Text, _>(submission.account_authority_id.as_str())
            .bind::<Text, _>(submission.principal_id.as_str())
            .bind::<Text, _>(result.accepted_device_id.as_str())
            .bind::<Text, _>(authorize_payload.device_public_key_did.as_str())
            .bind::<Jsonb, _>(&device_json)
            .bind::<Timestamptz, _>(result.commits[1].committed_at)
            .execute(&mut *conn)
            .await?;
            if device_inserted != 1 {
                return Err(PersistenceError::Conflict("founding_device_already_exists".to_owned()).into());
            }
            sql_query("UPDATE pcr_genesis_units SET commits_json=$2,result_json=$3 WHERE realm_id=$1")
                .bind::<Text, _>(realm_id)
                .bind::<Jsonb, _>(&commits_json)
                .bind::<Jsonb, _>(&result_json)
                .execute(&mut *conn)
                .await?;
            Ok(PcrGenesisCommitOutcome::Committed(result))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn admit_ordinary_realm_bootstrap_unit(
        &self,
        unit: &OrdinaryRealmBootstrapCommitUnit,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<OrdinaryRealmBootstrapCommitOutcome> {
        self.admit_ordinary_realm_bootstrap_unit_inner(unit, None, queued_at)
            .await
    }

    async fn admit_self_direct_conversation_founding_unit(
        &self,
        unit: &coland_storage::DirectConversationFoundingCommitUnit,
        producer_guards: &[SelfProducerCommitGuard; 4],
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<coland_storage::DirectConversationFoundingCommitOutcome> {
        crate::direct_conversation_founding::admit_self_direct_conversation_founding_unit(
            &self.pool,
            unit,
            producer_guards,
            queued_at,
        )
        .await
    }

    async fn materialize_peer_direct_conversation_founding_unit(
        &self,
        unit: &coland_storage::DirectConversationFoundingCommitUnit,
        evidence: &arkret_models_collaboration::objects::direct_conversation::DirectConversationFoundingAuthorityEvidence,
        local_station: &arkret_wire::DidCoreId,
        received_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus>
    {
        crate::direct_conversation_founding::materialize_peer_direct_conversation_founding_unit(
            &self.pool,
            unit,
            evidence,
            local_station,
            received_at,
        )
        .await
    }

    async fn direct_conversation_admission(
        &self,
        event: &arkret_wire::Event,
    ) -> PersistenceResult<coland_storage::DirectConversationAdmissionCut> {
        let mut conn = pg_conn(&self.pool).await?;
        // One snapshot, not read-only: the table share-locks the rows it
        // reads, exactly as inside the accepting transaction.
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .execute(&mut *conn)
                .await?;
            if crate::direct_conversation_admission::direct_conversation_realm_in_connection(
                conn,
                &event.realm_id,
            )
            .await?
            .is_none()
            {
                return Ok(coland_storage::DirectConversationAdmissionCut::NotDirectConversation);
            }
            Ok(
                match crate::direct_conversation_admission::admission_refusal_in_connection(
                    conn, event,
                )
                .await?
                {
                    Some(code) => coland_storage::DirectConversationAdmissionCut::Refused(code),
                    None => coland_storage::DirectConversationAdmissionCut::Passed,
                },
            )
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn direct_conversation_pending_peer_claim_query(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<coland_storage::DirectConversationPendingPeerClaimQuery>> {
        #[derive(QueryableByName)]
        struct Row {
            #[diesel(sql_type = Text)]
            peer_id: String,
            #[diesel(sql_type = Text)]
            original_request_body: String,
            #[diesel(sql_type = Text)]
            claim_request_id: String,
            #[diesel(sql_type = Text)]
            request_digest: String,
        }
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT o.peer_id, o.payload_json AS original_request_body, \
                    c.claim_request_id, c.request_digest \
             FROM direct_conversation_group_states g \
             JOIN federation_outbox fan \
               ON fan.endpoint='/_arkret/peer/events' \
              AND fan.payload_json::jsonb #>> '{replications,0,source_commit,event_ref}' \
                  =g.initial_exact_pair_group_state_ref \
             JOIN peer_keypackage_claims c \
               ON c.outcome #>> '{claims,0,claim_id}' \
                  =fan.payload_json::jsonb #>> '{replications,0,welcomes,0,keypackage_claim_ref}' \
             JOIN federation_outbox o \
               ON o.idempotency_key=c.claim_request_id \
              AND o.endpoint='/_arkret/peer/keys/keypackages/claim' \
              AND o.peer_id=fan.peer_id \
              AND o.peer_id=c.outcome->'claim_receipt'->>'destination_id' \
             WHERE g.realm_id=$1 AND c.state IN ('claimed','last_resort_claimed') \
             LIMIT 1",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<Row>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        Ok(row.map(
            |row| coland_storage::DirectConversationPendingPeerClaimQuery {
                peer_id: row.peer_id,
                original_request_body: row.original_request_body,
                claim_request_id: row.claim_request_id,
                request_digest: row.request_digest,
            },
        ))
    }

    async fn admit_self_ordinary_realm_bootstrap_unit(
        &self,
        unit: &OrdinaryRealmBootstrapCommitUnit,
        producer_guards: &[SelfProducerCommitGuard],
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<OrdinaryRealmBootstrapCommitOutcome> {
        self.admit_ordinary_realm_bootstrap_unit_inner(unit, Some(producer_guards), queued_at)
            .await
    }

    async fn install_genesis_authority(
        &self,
        authority: &CurrentRealmAuthority,
    ) -> PersistenceResult<()> {
        if authority.generation != 0
            || authority.last_handoff_ref.is_some()
            || !matches!(
                authority.authority_ref,
                arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(_)
            )
        {
            return Err(invalid(
                "genesis authority must use generation 0 without a handoff reference",
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query(
                "INSERT INTO realm_authorities \
                 (realm_id, generation, service_id, authority_ref, last_handoff_ref) VALUES ($1, 0, $2, $3, NULL) \
                 ON CONFLICT (realm_id) DO NOTHING",
            )
            .bind::<Text, _>(authority.realm_id.as_str())
            .bind::<Text, _>(authority.service_id.as_str())
            .bind::<Jsonb, _>(serde_json::to_value(&authority.authority_ref).map_err(PersistenceError::database)?)
            .execute(&mut *conn)
            .await?;
            let stored = locked_authority(conn, &authority.realm_id)
                .await?
                .ok_or_else(|| PersistenceError::Internal("genesis authority disappeared".into()))?;
            if !same_authority(&stored, authority) {
                return Err(PersistenceError::Conflict(
                    "realm authority already initialized differently".into(),
                )
                .into());
            }
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn record_remote_authority(
        &self,
        authority: &CurrentRealmAuthority,
        local_service_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            replica::record_remote_authority_in_connection(conn, authority, local_service_id).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn realm_fanout_still_owed(
        &self,
        event: &arkret_wire::Event,
        local_service_id: &arkret_wire::DidCoreId,
        peer: &arkret_wire::DidCoreId,
        witnesses: &[coland_storage::RealmFanoutAuthorityWitness],
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn)
                .await?;
            crate::realm_fanout::fanout_still_owed_in_connection(
                conn,
                event,
                local_service_id,
                peer,
                witnesses,
                at,
            )
            .await
            .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn install_committed_audit_pair(
        &self,
        request: &arkret_models_collaboration::authority_commit::AuditPairedEventFederationSubmission,
        replicas: &[coland_storage::CommittedReplica; 2],
    ) -> PersistenceResult<arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus>
    {
        request.validate().map_err(PersistenceError::database)?;
        for (slot, replica) in request.committed_events.iter().zip(replicas) {
            if slot.event_submission.event != replica.event
                || slot.source_commit != replica.commit
                || slot.producer_signer_fact != replica.producer_signer_fact
            {
                return Err(PersistenceError::SchemaViolation(
                    "audit replica differs from verified source slot".to_owned(),
                ));
            }
        }
        let canonical =
            arkret_canonical::canonical_json_bytes(request).map_err(PersistenceError::database)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            #[derive(diesel::QueryableByName)]
            struct Fence { #[diesel(sql_type=diesel::sql_types::Binary)] canonical_submission: Vec<u8> }
            crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &replicas[0].event.realm_id).await?;
            let original = sql_query("SELECT canonical_submission FROM registered_audit_replica_units WHERE business_event_id=$1 OR audit_event_id=$1 OR business_event_id=$2 OR audit_event_id=$2")
                .bind::<Text,_>(replicas[0].event.event_id.as_str()).bind::<Text,_>(replicas[1].event.event_id.as_str())
                .get_result::<Fence>(&mut *conn).await.optional()?;
            if original.as_ref().is_some_and(|original| original.canonical_submission != canonical) {
                return Err(PersistenceError::Conflict("duplicate_conflict: source audit pair has another complete submission".to_owned()).into());
            }
            if original.is_none() {
                #[derive(diesel::QueryableByName)]
                struct Existing { #[diesel(sql_type=diesel::sql_types::Bool)] present: bool }
                let existing = sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events WHERE envelope->>'event_id' IN ($1,$2)) AS present")
                    .bind::<Text,_>(replicas[0].event.event_id.as_str()).bind::<Text,_>(replicas[1].event.event_id.as_str())
                    .get_result::<Existing>(&mut *conn).await?;
                if existing.present { return Err(PersistenceError::Conflict("revision_unavailable: existing source slot has no complete unit fence".to_owned()).into()); }
            }
            let first = replica::install_registered_replica_in_connection(conn, &replicas[0]).await?;
            let second = replica::install_registered_replica_in_connection(conn, &replicas[1]).await?;
            if matches!((first,second), (coland_storage::CommittedReplicaOutcome::Stored,coland_storage::CommittedReplicaOutcome::Duplicate) | (coland_storage::CommittedReplicaOutcome::Duplicate,coland_storage::CommittedReplicaOutcome::Stored)) {
                return Err(PersistenceError::Conflict("revision_unavailable: audit pair has a partial source installation".to_owned()).into());
            }
            if original.is_none() {
                sql_query("INSERT INTO registered_audit_replica_units(business_event_id,audit_event_id,realm_id,canonical_submission) VALUES($1,$2,$3,$4)")
                    .bind::<Text,_>(replicas[0].event.event_id.as_str()).bind::<Text,_>(replicas[1].event.event_id.as_str())
                    .bind::<Text,_>(replicas[0].event.realm_id.as_str()).bind::<diesel::sql_types::Binary,_>(&canonical)
                    .execute(&mut *conn).await?;
            }
            Ok(if first==coland_storage::CommittedReplicaOutcome::Duplicate { arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Duplicate } else { arkret_models_collaboration::authority_commit::AggregateAcceptanceStatus::Committed })
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn install_committed_replica(
        &self,
        replica: &coland_storage::CommittedReplica,
    ) -> PersistenceResult<coland_storage::CommittedReplicaOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            replica::install_committed_replica_in_connection(conn, replica).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn install_committed_peer_replica(
        &self,
        replica: &coland_storage::CommittedReplica,
        receipt: &coland_storage::IdempotencyRecord,
    ) -> PersistenceResult<(coland_storage::CommittedReplicaOutcome, bool)> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            replica::install_committed_peer_replica_in_connection(conn, replica, receipt).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn queue_replicated_welcomes(
        &self,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        genesis_event_ref: Option<&arkret_wire::EventId>,
        welcomes: &[coland_storage::VerifiedMlsWelcome],
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<coland_storage::CommittedReplicaOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            replica::queue_welcomes_of_held_replica_in_connection(
                conn,
                event,
                commit,
                genesis_event_ref,
                welcomes,
                at,
            )
            .await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn install_committed_chain_node(
        &self,
        node: &coland_storage::CommittedChainNode,
    ) -> PersistenceResult<coland_storage::CommittedReplicaOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            replica::install_committed_chain_node_in_connection(conn, node).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn replica_stream_anchor(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<coland_storage::ReplicaStreamAnchor>> {
        let mut conn = pg_conn(&self.pool).await?;
        replica::replica_stream_anchor_in_connection(&mut conn, realm_id)
            .await
            .map_err(PgTransactionError::into_persistence)
    }

    async fn pending_franking_proofs(
        &self,
        receiver: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Vec<coland_storage::PendingFrankingProof>> {
        let mut conn = pg_conn(&self.pool).await?;
        crate::moderation_franking_proof_current_results::pending_franking_in_connection(
            &mut conn, receiver,
        )
        .await
    }

    async fn fix_franking_proof(
        &self,
        prepared: &coland_storage::PreparedFrankingProof,
    ) -> PersistenceResult<arkret_wire::Event> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(
                crate::moderation_franking_proof_current_results::fix_franking_in_connection(
                    conn, prepared,
                )
                .await?,
            )
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn complete_franking_proof(
        &self,
        realm: &arkret_wire::RealmId,
        target: &arkret_wire::EventId,
        proof_event: &arkret_wire::EventId,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        crate::moderation_franking_proof_current_results::complete_franking_in_connection(
            &mut conn,
            realm,
            target,
            proof_event,
        )
        .await
    }

    async fn replica_anchor_for_stream(
        &self,
        stream: &arkret_wire::CommitStreamRef,
    ) -> PersistenceResult<Option<coland_storage::ReplicaStreamAnchor>> {
        let mut conn = pg_conn(&self.pool).await?;
        replica::replica_anchor_for_stream_in_connection(&mut conn, stream)
            .await
            .map_err(PgTransactionError::into_persistence)
    }

    async fn accepted_own_leave_bound_result(
        &self,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        account: &arkret_wire::AccountId,
        local_service: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<bool> {
        use arkret_models_collaboration::authority_commit::{
            HumanHistoricalSignerFact, SelfAuthoritySubmitRequest,
        };
        use arkret_models_collaboration::events_payloads::CircleMemberStatePayload;
        use arkret_models_collaboration::governance::circle::CircleMembership;
        use arkret_models_collaboration::governance::membership_invite::{
            MembershipPayload, MembershipPayloadState,
        };
        let actor = arkret_wire::ActorId::account(account.clone());
        let stream = match (&event.kind, &event.scope_ref) {
            (arkret_wire::EventKind::MemberState, arkret_wire::ScopeRef::Realm { realm_id })
                if realm_id == &event.realm_id =>
            {
                arkret_wire::CommitStreamRef::Realm {
                    realm_id: realm_id.clone(),
                }
            }
            (
                arkret_wire::EventKind::CircleMemberState,
                arkret_wire::ScopeRef::Circle {
                    realm_id,
                    circle_id,
                },
            ) if realm_id == &event.realm_id => arkret_wire::CommitStreamRef::Circle {
                realm_id: event.realm_id.clone(),
                circle_id: circle_id.clone(),
            },
            _ => return Ok(false),
        };
        if event.actor_id != actor
            || event.executed_by.is_some()
            || account.station_id != *local_service
            || commit.stream_ref != stream
            || commit.realm_id != event.realm_id
            || commit.event_ref != event.event_id
            || event.human_device_producer().map_err(invalid)?.is_none()
        {
            return Ok(false);
        }
        let circle_leave = match &stream {
            arkret_wire::CommitStreamRef::Realm { .. } => {
                let payload: MembershipPayload = serde_json::from_value(
                    serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                )
                .map_err(invalid)?;
                if payload.membership != MembershipPayloadState::Leave
                    || payload.member_id != actor
                    || payload
                        .realm_id
                        .as_ref()
                        .is_some_and(|realm| realm != &event.realm_id)
                {
                    return Ok(false);
                }
                None
            }
            arkret_wire::CommitStreamRef::Circle { circle_id, .. } => {
                let payload: CircleMemberStatePayload = serde_json::from_value(
                    serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                )
                .map_err(invalid)?;
                if payload.membership != CircleMembership::Leave
                    || payload.member_id != actor
                    || &payload.circle_id != circle_id
                {
                    return Ok(false);
                }
                Some(payload)
            }
            _ => return Ok(false),
        };
        event
            .verify_event_id_matches_content_with_digest_suite(
                event.event_id.digest_suite_code().digest_suite(),
            )
            .map_err(invalid)?;
        commit.validate_shape().map_err(invalid)?;
        commit.verify_commit_id_matches_content().map_err(invalid)?;
        #[derive(QueryableByName)]
        struct BoundLeaveRow {
            #[diesel(sql_type=Nullable<Jsonb>)]
            circle_leave_parent_revision: Option<Value>,
            #[diesel(sql_type=Jsonb)]
            envelope: Value,
            #[diesel(sql_type=Jsonb)]
            commit_json: Value,
            #[diesel(sql_type=Jsonb)]
            submission_json: Value,
            #[diesel(sql_type=Jsonb)]
            accepted_json: Value,
            #[diesel(sql_type=Jsonb)]
            fact_json: Value,
            #[diesel(sql_type=Jsonb)]
            member_value: Value,
            #[diesel(sql_type=Jsonb)]
            join_envelope: Value,
            #[diesel(sql_type=Jsonb)]
            join_commit_json: Value,
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY").execute(&mut *conn).await?;
            // The durable opening member proves the Station's prefix, not the
            // identity of every later hosted submitter. Bind the own leave to
            // that Account's latest accepted membership predecessor instead.
            let row = sql_query(
                "SELECT e.envelope,c.commit_json,f.circle_leave_parent_revision,f.original_submission_json AS submission_json, \
                 f.accepted_commit_json AS accepted_json,k.producer_source_fact AS fact_json, \
                 m.value AS member_value,j.envelope AS join_envelope,jc.commit_json AS join_commit_json \
                 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
                 JOIN authority_forward_attempts f ON f.event_pk=e.pk \
                 JOIN (SELECT realm_id,member_id,membership,current_commit_id,current_stream_position,value, \
                       jsonb_build_object('kind','realm','realm_id',realm_id) AS source_stream_ref \
                       FROM member_state_current_results \
                       UNION ALL SELECT realm_id,member_id,membership,current_commit_id,current_stream_position,value, \
                       source_stream_ref FROM circle_member_state_current_results \
                       WHERE source_stream_ref->>'circle_id'=circle_id) m \
                   ON m.realm_id=c.realm_id AND m.member_id=$2 AND m.source_stream_ref=c.stream_ref \
                 JOIN replica_stream_anchors a ON a.realm_id=c.realm_id AND a.stream_key=c.stream_key \
                 JOIN realm_commits opening ON opening.commit_id=a.join_commit_id \
                 JOIN canonical_events oe ON oe.pk=opening.event_pk AND oe.state='committed' \
                 JOIN LATERAL (SELECT prior.* FROM realm_commits prior \
                   JOIN canonical_events pe ON pe.pk=prior.event_pk AND pe.state='committed' \
                   WHERE prior.realm_id=c.realm_id AND prior.stream_key=c.stream_key AND prior.stream_ref=c.stream_ref \
                     AND prior.stream_position<c.stream_position \
                     AND ((pe.kind='ak.invite.accept' AND pe.envelope->'actor_id'=$8) \
                       OR (pe.kind IN ('ak.member.state','ak.circle.member.state') \
                           AND pe.envelope->'payload'->'member_id'=$8)) \
                   ORDER BY prior.stream_position DESC LIMIT 1) jc ON true \
                 JOIN canonical_events j ON j.pk=jc.event_pk \
                 JOIN agent_producer_signer_keys k ON k.commit_id=c.commit_id \
                 WHERE e.id=$1 AND e.state='committed' AND j.state='committed' \
                   AND c.commit_id=$3 AND c.realm_id=$4 AND c.stream_ref=$5 AND c.stream_position=$6 \
                   AND m.membership='leave' AND m.current_commit_id=c.commit_id \
                   AND m.current_stream_position=c.stream_position \
                   AND a.member_account_id->>'station_id'=$7::jsonb->>'station_id' AND a.anchor_commit_id IS NOT NULL \
                   AND opening.realm_id=c.realm_id AND opening.stream_key=c.stream_key AND opening.stream_ref=c.stream_ref \
                   AND opening.stream_position<=jc.stream_position \
                   AND oe.envelope->'actor_id'=jsonb_build_object('kind','account','account_id',a.member_account_id) \
                   AND ((oe.kind='ak.invite.accept' AND c.stream_ref->>'kind'='realm') \
                     OR (oe.kind IN ('ak.member.state','ak.circle.member.state') \
                       AND oe.envelope->'payload'->>'membership'='join' \
                       AND oe.envelope->'payload'->'member_id'=oe.envelope->'actor_id')) \
                   AND jc.realm_id=c.realm_id AND jc.stream_key=c.stream_key AND jc.stream_ref=c.stream_ref \
                   AND jc.stream_position<c.stream_position \
                   AND f.original_submission_json IS NOT NULL AND f.accepted_commit_json IS NOT NULL \
                   AND k.producer_source_fact IS NOT NULL"
            ).bind::<Binary,_>(event.event_id.token_bytes().to_vec())
             .bind::<Text,_>(actor.to_string()).bind::<Text,_>(commit.commit_id.as_str())
             .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&stream).map_err(PersistenceError::database)?)
             .bind::<BigInt,_>(i64::try_from(commit.stream_position).map_err(PersistenceError::database)?)
             .bind::<Jsonb,_>(serde_json::to_value(account).map_err(PersistenceError::database)?)
             .bind::<Jsonb,_>(serde_json::to_value(&actor).map_err(PersistenceError::database)?)
             .get_result::<BoundLeaveRow>(&mut *conn).await.optional()?;
            let Some(row) = row else { return Ok(false); };
            let held_event: arkret_wire::Event = decode_json(row.envelope, "bound leave Event")?;
            let held_commit: arkret_wire::RealmCommit = decode_json(row.commit_json, "bound leave Commit")?;
            let accepted: arkret_wire::RealmCommit = decode_json(row.accepted_json, "bound leave accepted witness")?;
            let submission: SelfAuthoritySubmitRequest = decode_json(row.submission_json, "bound leave original intent")?;
            let fact: HumanHistoricalSignerFact = decode_json(row.fact_json, "bound leave original fact")?;
            let join_event: arkret_wire::Event = decode_json(row.join_envelope, "bound leave opening Event")?;
            let join_commit: arkret_wire::RealmCommit = decode_json(row.join_commit_json, "bound leave opening Commit")?;
            let SelfAuthoritySubmitRequest::Event(submitted) = submission else { return Ok(false); };
            if held_event != *event || held_commit != *commit || accepted != *commit || submitted.event != *event
                || join_event.actor_id != actor || join_event.realm_id != event.realm_id
                || join_event.scope_ref != event.scope_ref || join_commit.event_ref != join_event.event_id
                || join_commit.stream_ref != stream
            { return Ok(false); }
            let current_matches = if let Some(payload) = &circle_leave {
                let member: arkret_wire::CircleMemberStateCurrent = decode_json(row.member_value, "bound Circle leave effective membership")?;
                member.membership == arkret_wire::MembershipState::Leave
                    && member.parent_membership_revision.is_none()
                    && member.effective_at == payload.effective_at.unwrap_or(event.created_at)
            } else {
                let member: arkret_wire::MemberStateCurrent = decode_json(row.member_value, "bound leave effective membership")?;
                member == (arkret_wire::MemberStateCurrent { membership: arkret_wire::MembershipState::Leave, joined_at: None })
            };
            if !current_matches { return Ok(false); }
            let own_join = match join_event.kind {
                arkret_wire::EventKind::InviteAccept if circle_leave.is_none() => true,
                arkret_wire::EventKind::MemberState if circle_leave.is_none() => {
                    let value: MembershipPayload = serde_json::from_value(serde_json::to_value(&join_event.payload)
                        .map_err(PersistenceError::database)?).map_err(invalid)?;
                    value.membership == MembershipPayloadState::Join && value.member_id == actor
                        && value.realm_id.as_ref().is_none_or(|realm| realm == &event.realm_id)
                }
                arkret_wire::EventKind::CircleMemberState if circle_leave.is_some() => {
                    let value: CircleMemberStatePayload = serde_json::from_value(serde_json::to_value(&join_event.payload)
                        .map_err(PersistenceError::database)?).map_err(invalid)?;
                    value.membership == CircleMembership::Join
                        && value.member_id == actor && Some(&value.circle_id) == circle_leave.as_ref().map(|leave| &leave.circle_id)
                        && value.parent_membership_revision.is_some()
                        && match row.circle_leave_parent_revision {
                            Some(bound) => {
                                let bound: arkret_wire::CurrentRevision = decode_json(bound, "bound Circle leave parent revision")?;
                                parent_join_at_revision_in_connection(conn, &event.realm_id, &actor, &bound).await?
                            },
                            None => false,
                        }
                }
                _ => false,
            };
            if !own_join { return Ok(false); }
            join_event.verify_event_id_matches_content_with_digest_suite(join_event.event_id.digest_suite_code().digest_suite()).map_err(invalid)?;
            join_commit.validate_shape().map_err(invalid)?;
            join_commit.verify_commit_id_matches_content().map_err(invalid)?;
            fact.validate_commit_binding(&arkret_wire::CommittedEventFullView { event: held_event, commit: held_commit },
                event.event_id.digest_suite_code().digest_suite()).map_err(invalid)?;
            Ok(true)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn circle_views_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Vec<arkret_models_collaboration::governance::circle::CircleView>> {
        crate::circle_reads::circle_views_for_actor(&self.pool, realm_id, actor).await
    }

    async fn circle_reads_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Vec<arkret_models_collaboration::governance::circle::CircleReadView>>
    {
        crate::circle_reads::circle_reads_for_actor(&self.pool, realm_id, actor).await
    }

    async fn circle_view_for_actor(
        &self,
        circle_id: &arkret_wire::CircleId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Option<arkret_models_collaboration::governance::circle::CircleView>>
    {
        crate::circle_reads::circle_view_for_actor(&self.pool, circle_id, actor).await
    }

    async fn circle_read_for_actor(
        &self,
        circle_id: &arkret_wire::CircleId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Option<arkret_models_collaboration::governance::circle::CircleReadView>>
    {
        crate::circle_reads::circle_read_for_actor(&self.pool, circle_id, actor).await
    }

    async fn replica_authorization_head(
        &self,
        stream: &arkret_wire::CommitStreamRef,
    ) -> PersistenceResult<Option<arkret_wire::CommitStreamHead>> {
        let mut conn = pg_conn(&self.pool).await?;
        crate::replica_authorization::verified_head(&mut conn, stream).await
    }

    async fn replica_bootstrap_readers(
        &self,
        stream: &arkret_wire::CommitStreamRef,
        local_service: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Vec<(arkret_wire::AccountId, arkret_wire::RealmCommit)>> {
        let mut conn = pg_conn(&self.pool).await?;
        replica::bootstrap_readers_in_connection(&mut conn, stream, local_service, false)
            .await
            .map_err(PgTransactionError::into_persistence)
    }

    async fn pending_replica_streams(
        &self,
    ) -> PersistenceResult<Vec<arkret_wire::CommitStreamRef>> {
        #[derive(QueryableByName)]
        struct StreamRow {
            #[diesel(sql_type=Jsonb)]
            stream_ref: serde_json::Value,
        }
        let mut conn = pg_conn(&self.pool).await?;
        sql_query("SELECT c.stream_ref FROM replica_stream_anchors a JOIN realm_commits c ON c.commit_id=a.join_commit_id WHERE a.anchor_commit_id IS NULL OR NOT EXISTS(SELECT 1 FROM replica_authorization_cuts cut WHERE cut.realm_id=a.realm_id AND cut.source_stream_ref=jsonb_build_object('kind','realm','realm_id',a.realm_id)) ORDER BY a.stream_key")
            .load::<StreamRow>(&mut conn).await.map_err(PersistenceError::database)?.into_iter().map(|row| decode_json(row.stream_ref, "pending replica stream")).collect()
    }

    async fn pending_replica_stream_anchors(&self) -> PersistenceResult<Vec<arkret_wire::RealmId>> {
        #[derive(QueryableByName)]
        struct RealmRow {
            #[diesel(sql_type = Text)]
            realm_id: String,
        }
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT realm_id FROM replica_stream_anchors \
             WHERE anchor_commit_id IS NULL ORDER BY realm_id",
        )
        .load::<RealmRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(|row| decode_text(row.realm_id, "pending replica Realm id"))
        .collect()
    }

    async fn install_replica_anchor(
        &self,
        install: &coland_storage::ReplicaAnchorInstall,
    ) -> PersistenceResult<()> {
        let mut conn = crate::issued_realm_snapshots::SnapshotIssuanceConnection::acquire(
            &self.pool,
            &install.realm_id,
        )
        .await?;
        let result = conn
            .transaction::<_, PgTransactionError, _>(async move |conn| {
                replica::install_replica_anchor_in_connection(conn, install).await
            })
            .await
            .map_err(PgTransactionError::into_persistence);
        conn.finish(result).await
    }

    async fn held_stream_head_commit(
        &self,
        stream_ref: &arkret_wire::CommitStreamRef,
    ) -> PersistenceResult<Option<arkret_wire::RealmCommit>> {
        let key = stream_key(stream_ref)?;
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT commit_json FROM realm_commits \
             WHERE stream_key = $1 ORDER BY stream_position DESC LIMIT 1",
        )
        .bind::<Text, _>(key)
        .get_result::<CommitRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| decode_json(row.commit_json, "held stream head"))
        .transpose()
    }

    async fn watch_audit_read_delivery_guard(
        &self,
        request: &arkret_models_collaboration::strand_watch_operations::WatchAuditReadRequest,
        outcome: &arkret_models_collaboration::strand_watch_operations::WatchAuditReadOutcome,
        issuer: &arkret_wire::DidCoreId,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Box<dyn coland_storage::AccountContentDeliveryGuard>> {
        crate::account_content_delivery::acquire_governor_audit_delivery(
            &self.pool, request, outcome, issuer, expires_at,
        )
        .await
    }

    async fn watch_audit_read_disclosure(
        &self,
        request: &arkret_models_collaboration::strand_watch_operations::WatchAuditReadRequest,
        outcome: &arkret_models_collaboration::strand_watch_operations::WatchAuditReadOutcome,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<()> {
        outcome
            .validate_for_request(request, outcome.audit_commit.governance_generation)
            .map_err(PersistenceError::database)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            crate::registered_audit::read_visibility_in_connection(
                conn,
                request,
                issuer,
                Some(outcome.audit_commit.governance_generation),
            )
            .await?;
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn registered_audit_result(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<coland_storage::RegisteredAuditResult>> {
        let mut conn = pg_conn(&self.pool).await?;
        crate::registered_audit::original_in_connection(&mut conn, event_id).await
    }

    async fn current_authority(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<CurrentRealmAuthority>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT realm_id, generation, service_id, authority_ref, last_handoff_ref \
             FROM realm_authorities WHERE realm_id = $1",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<AuthorityRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(authority_from_row).transpose()
    }

    async fn local_current_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        member: &arkret_wire::ActorId,
        service_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT EXISTS (\
                SELECT 1 FROM realm_authorities a \
                JOIN member_state_current_results m ON m.realm_id = a.realm_id \
                JOIN realm_commits c ON c.commit_id = m.current_commit_id \
                WHERE a.realm_id = $1 AND a.service_id = $2 \
                  AND m.member_id = $3 AND m.membership = 'join' \
                  AND c.realm_id = m.realm_id \
                  AND c.stream_position = m.current_stream_position \
                  AND c.stream_ref->>'kind' = 'realm' \
                  AND c.stream_ref->>'realm_id' = m.realm_id\
             ) AS present",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(service_id.as_str())
        .bind::<Text, _>(member.to_string())
        .get_result::<PresenceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(row.present)
    }

    async fn accepted_current_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        member: &arkret_wire::ActorId,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        accepted_current_member_joined_in_connection(&mut conn, realm_id, member).await
    }

    async fn replica_stream_has_hosted_member(
        &self,
        stream: &arkret_wire::CommitStreamRef,
        local_service_id: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<bool>> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .execute(conn)
                .await?;
            let anchor = replica::replica_anchor_for_stream_in_connection(conn, stream).await?;
            let Some(anchor) = anchor else {
                return Ok(None);
            };
            Ok(Some(
                anchor.anchored_head.is_some()
                    && replica::hosts_joined_member_in_snapshot(conn, stream, local_service_id)
                        .await?,
            ))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn require_held_replica_write_lifecycle(
        &self,
        event: &arkret_wire::Event,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .execute(conn)
                .await?;
            let parent = arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            };
            if replica::replica_anchor_for_stream_in_connection(conn, &parent)
                .await?
                .is_some()
            {
                crate::realm_lifecycle_current_results::require_replica_live_in_connection(
                    conn, event,
                )
                .await?;
            }
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn accepted_ordinary_realm(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<bool> {
        use arkret_models_collaboration::events_payloads::realm::{RealmGenesis, RealmPurpose};
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT g.value FROM realm_bootstrap_current_results g \
             WHERE g.realm_id=$1 AND g.result_family='realm_genesis' \
               AND (EXISTS(SELECT 1 FROM realm_commits c \
                    WHERE c.commit_id=g.current_commit_id AND c.realm_id=g.realm_id \
                      AND c.stream_position=g.current_stream_position \
                      AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',g.realm_id)) \
                 OR EXISTS(SELECT 1 FROM replica_stream_anchors a \
                    WHERE a.realm_id=g.realm_id AND a.stream_key=$2 \
                      AND a.anchor_stream_position>=g.current_stream_position))",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(stream_key(&arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        })?)
        .get_result::<ProducerCurrentValueRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        let Some(row) = row else {
            return Ok(false);
        };
        let genesis: RealmGenesis = decode_json(row.value, "accepted Realm genesis")?;
        genesis.validate().map_err(PersistenceError::database)?;
        Ok(matches!(
            genesis.purpose,
            RealmPurpose::Collaboration | RealmPurpose::DirectConversation
        ))
    }

    async fn accepted_realm_roster(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<coland_storage::AcceptedRealmRoster>> {
        let mut conn = pg_conn(&self.pool).await?;
        accepted_realm_roster_in_connection(&mut conn, realm_id).await
    }

    async fn accepted_effective_agent_member_joined(
        &self,
        realm_id: &arkret_wire::RealmId,
        agent: &arkret_wire::ActorId,
        controller: &arkret_wire::AccountId,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        let controller_actor = arkret_wire::ActorId::account(controller.clone());
        let controller_value =
            serde_json::to_value(controller).map_err(PersistenceError::database)?;
        let row = sql_query(
            "SELECT EXISTS (\
               SELECT 1 FROM member_state_current_results agent_member \
               JOIN realm_commits agent_commit \
                 ON agent_commit.commit_id=agent_member.current_commit_id \
                AND agent_commit.realm_id=agent_member.realm_id \
                AND agent_commit.stream_position=agent_member.current_stream_position \
                AND agent_commit.stream_ref->>'kind'='realm' \
               JOIN canonical_events agent_event ON agent_event.pk=agent_commit.event_pk \
               JOIN member_state_current_results controller_member \
                 ON controller_member.realm_id=agent_member.realm_id \
               JOIN realm_commits controller_commit \
                 ON controller_commit.commit_id=controller_member.current_commit_id \
                AND controller_commit.realm_id=controller_member.realm_id \
                AND controller_commit.stream_position=controller_member.current_stream_position \
                AND controller_commit.stream_ref->>'kind'='realm' \
               JOIN canonical_events controller_event ON controller_event.pk=controller_commit.event_pk \
               WHERE agent_member.realm_id=$1 AND agent_member.member_id=$2 \
                 AND agent_member.membership='join' \
                 AND controller_member.member_id=$3 AND controller_member.membership='join' \
                 AND agent_event.envelope->'payload'->'agent_controller_binding'->'controller_account_id'=$4 \
                 AND agent_event.envelope->'payload'->'agent_controller_binding'->>'controller_membership_generation_ref' \
                     =controller_event.envelope->>'event_id' \
                 AND agent_event.kind='ak.member.state' \
             ) AS present",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(agent.to_string())
        .bind::<Text, _>(controller_actor.to_string())
        .bind::<Jsonb, _>(controller_value)
        .get_result::<PresenceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        Ok(row.present)
    }

    async fn accepted_realm_reader(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn)
                .await?;
            if accepted_current_member_joined_in_connection(conn, realm_id, actor).await? {
                if let Some(controller) =
                    crate::agent_management_admission::read_controller_in_connection(
                        conn, realm_id, None, actor,
                    )
                    .await?
                {
                    return Ok(accepted_current_member_joined_in_connection(
                        conn,
                        realm_id,
                        &controller,
                    )
                    .await?);
                }
                return Ok(true);
            }
            let Some(account) = actor.as_account_id() else {
                return Ok(false);
            };
            // The owner Account's principal-control Realm, recorded in the same
            // transaction as its PCR genesis.
            Ok(sql_query(
                "SELECT EXISTS (SELECT 1 FROM principal_resolutions \
             WHERE pcr_realm_id = $1 AND principal_id = $2 AND station_id = $3) AS present",
            )
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(account.principal_id.as_str())
            .bind::<Text, _>(account.station_id.as_str())
            .get_result::<PresenceRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
            .present)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn accepted_plaintext_visible_services(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<
        Option<
            arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload,
        >,
    >{
        #[derive(QueryableByName)]
        struct ValueRow {
            #[diesel(sql_type = Jsonb)]
            value: Value,
        }
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT b.value FROM realm_bootstrap_current_results b \
             WHERE b.realm_id = $1 AND b.result_family = 'realm_plaintext_visible_services' \
               AND (EXISTS (SELECT 1 FROM realm_commits c \
                            WHERE c.commit_id = b.current_commit_id \
                              AND c.realm_id = b.realm_id \
                              AND c.stream_position = b.current_stream_position \
                              AND c.stream_ref->>'kind' = 'realm' \
                              AND c.stream_ref->>'realm_id' = b.realm_id) \
                    OR EXISTS (SELECT 1 FROM replica_stream_anchors a \
                               WHERE a.realm_id = b.realm_id AND a.stream_key = $2 \
                                 AND a.anchor_stream_position >= b.current_stream_position))",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(stream_key(&arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        })?)
        .get_result::<ValueRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| decode_json(row.value, "Realm plaintext-visible services"))
        .transpose()
    }

    async fn queue_event(
        &self,
        event: &arkret_wire::Event,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            queue_event_in_connection(conn, event, queued_at).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn retain_forwarded_submission(
        &self,
        event: &arkret_wire::Event,
        submission: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
        submission.validate().map_err(|e| invalid(e.to_string()))?;
        event
            .verify_event_id_matches_content_with_digest_suite(
                event.event_id.digest_suite_code().digest_suite(),
            )
            .map_err(invalid)?;
        let submitted = match submission {
            SelfAuthoritySubmitRequest::Event(value) => &value.event,
            SelfAuthoritySubmitRequest::MlsCommit(value) => &value.commit_event,
            _ => {
                return Err(invalid(
                    "only an Event or MLS forwarding intent may be retained",
                ));
            }
        };
        if submitted != event {
            return Err(forward_original_conflict(
                "forward intent differs from its Event",
            ));
        }
        let token = ids::parse_event_id(event.event_id.as_str())
            .ok_or_else(|| invalid("invalid Event token"))?;
        let mut conn = pg_conn(&self.pool).await?;
        // Freeze the parent cut before sending the original own Circle leave.
        // Its old canonical join may already be effective-invalid after a
        // parent rejoin; that does not authorize content, but the new exact
        // parent cut can bind delivery of this explicit cleanup write result.
        let own_circle_leave = if event.kind == arkret_wire::EventKind::CircleMemberState
            && matches!(event.scope_ref, arkret_wire::ScopeRef::Circle { .. })
            && event.actor_id.as_account_id().is_some()
            && event.executed_by.is_none()
        {
            let payload: arkret_models_collaboration::events_payloads::CircleMemberStatePayload =
                serde_json::from_value(
                    serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                )
                .map_err(invalid)?;
            payload.membership
                == arkret_models_collaboration::governance::circle::CircleMembership::Leave
                && payload.member_id == event.actor_id
        } else {
            false
        };
        let written = sql_query(
            "INSERT INTO authority_forward_attempts (event_pk,status,reason_code,attempted_at,original_submission_json,circle_leave_parent_revision) \
             SELECT e.pk,'forwarding',NULL,$3,$2, \
                 CASE WHEN $5 THEN (SELECT jsonb_build_object('commit_id',m.current_commit_id,'stream_position',m.current_stream_position) \
                    FROM member_state_current_results m WHERE m.realm_id=$6 AND m.member_id=$7 AND m.membership='join' \
                      AND (EXISTS(SELECT 1 FROM realm_commits c WHERE c.commit_id=m.current_commit_id AND c.realm_id=m.realm_id \
                           AND c.stream_position=m.current_stream_position AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',m.realm_id)) \
                        OR EXISTS(SELECT 1 FROM replica_stream_anchors a WHERE a.realm_id=m.realm_id AND a.stream_key=$8 \
                           AND a.anchor_stream_position>=m.current_stream_position))) END \
             FROM canonical_events e WHERE e.id=$1 AND e.envelope=$4 \
             ON CONFLICT(event_pk) DO UPDATE SET original_submission_json=EXCLUDED.original_submission_json, \
                circle_leave_parent_revision=CASE WHEN authority_forward_attempts.original_submission_json IS NULL \
                  THEN EXCLUDED.circle_leave_parent_revision ELSE authority_forward_attempts.circle_leave_parent_revision END \
             WHERE authority_forward_attempts.original_submission_json IS NULL \
                OR authority_forward_attempts.original_submission_json=EXCLUDED.original_submission_json"
        ).bind::<Binary,_>(token.to_vec()).bind::<Jsonb,_>(serde_json::to_value(submission).map_err(PersistenceError::database)?)
         .bind::<Timestamptz,_>(at).bind::<Jsonb,_>(serde_json::to_value(event).map_err(PersistenceError::database)?)
         .bind::<Bool,_>(own_circle_leave).bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.actor_id.to_string())
         .bind::<Text,_>(stream_key(&arkret_wire::CommitStreamRef::Realm { realm_id: event.realm_id.clone() })?)
         .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        if written != 1 {
            return Err(forward_original_conflict(
                "forward intent differs from its queued original",
            ));
        }
        Ok(())
    }

    async fn retain_forwarded_acceptance(
        &self,
        event: &arkret_wire::Event,
        commit: &arkret_wire::RealmCommit,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        event
            .validate_for_submit_structural()
            .map_err(|e| invalid(e.to_string()))?;
        event
            .verify_event_id_matches_content_with_digest_suite(
                event.event_id.digest_suite_code().digest_suite(),
            )
            .map_err(invalid)?;
        commit
            .validate_shape()
            .map_err(|e| invalid(e.to_string()))?;
        commit.verify_commit_id_matches_content().map_err(invalid)?;
        if commit.event_ref != event.event_id
            || commit.realm_id != event.realm_id
            || commit.stream_ref
                != arkret_wire::CommitStreamRef::from_scope(
                    &event.scope_ref,
                    Some(event.realm_id.clone()),
                )
                .map_err(|e| invalid(e.to_string()))?
        {
            return Err(invalid(
                "forward acceptance does not bind its exact Event and stream",
            ));
        }
        let token = ids::parse_event_id(event.event_id.as_str())
            .ok_or_else(|| invalid("invalid Event token"))?;
        let mut conn = pg_conn(&self.pool).await?;
        let written = sql_query(
            "UPDATE authority_forward_attempts f SET accepted_commit_json=$2,status='forwarding',reason_code=NULL,attempted_at=$3 \
             FROM canonical_events e WHERE f.event_pk=e.pk AND e.id=$1 AND e.envelope=$4 \
               AND f.original_submission_json IS NOT NULL \
               AND (f.accepted_commit_json IS NULL OR f.accepted_commit_json=$2)"
        ).bind::<Binary,_>(token.to_vec()).bind::<Jsonb,_>(serde_json::to_value(commit).map_err(PersistenceError::database)?)
         .bind::<Timestamptz,_>(at).bind::<Jsonb,_>(serde_json::to_value(event).map_err(PersistenceError::database)?)
         .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        if written != 1 {
            return Err(forward_original_conflict(
                "forward acceptance differs from its frozen original",
            ));
        }
        Ok(())
    }

    async fn record_forward_attempt(
        &self,
        event_id: &arkret_wire::EventId,
        status: ForwardAttemptStatus,
        reason_code: Option<&str>,
        attempted_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        if (status == ForwardAttemptStatus::Rejected) != reason_code.is_some() {
            return Err(invalid("forward attempt reason does not match status"));
        }
        let token = ids::parse_event_id(event_id.as_str())
            .ok_or_else(|| invalid("Event id is not a canonical Event token"))?;
        let mut conn = pg_conn(&self.pool).await?;
        let written = sql_query(
            "INSERT INTO authority_forward_attempts (event_pk,status,reason_code,attempted_at) \
             SELECT pk,$2,$3,$4 FROM canonical_events WHERE id=$1 \
             ON CONFLICT (event_pk) DO UPDATE SET \
             status=CASE WHEN authority_forward_attempts.accepted_commit_json IS NOT NULL THEN 'forwarding' ELSE EXCLUDED.status END, \
             reason_code=CASE WHEN authority_forward_attempts.accepted_commit_json IS NOT NULL THEN NULL ELSE EXCLUDED.reason_code END, \
             attempted_at=EXCLUDED.attempted_at",
        )
        .bind::<Binary, _>(token.to_vec())
        .bind::<Text, _>(status.as_str())
        .bind::<Nullable<Text>, _>(reason_code)
        .bind::<Timestamptz, _>(attempted_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if written != 1 {
            return Err(PersistenceError::Internal(
                "forward attempt has no queued Event".to_owned(),
            ));
        }
        Ok(())
    }

    async fn finalize_mls_rejection(
        &self,
        event: &arkret_wire::Event,
        authority: &CurrentRealmAuthority,
        reason_code: &str,
    ) -> PersistenceResult<arkret_wire::AuthoritySubmitOutcome> {
        if event.kind != arkret_wire::EventKind::MlsCommit || event.realm_id != authority.realm_id {
            return Err(invalid(
                "only an exact ordinary MLS Commit can receive this refusal fence",
            ));
        }
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let current = locked_authority(conn, &event.realm_id).await?
                .ok_or_else(|| invalid("MLS refusal has no governance authority"))?;
            queue_event_in_connection(conn, event, chrono::Utc::now()).await?;
            let token = ids::parse_event_id(event.event_id.as_str()).ok_or_else(|| invalid("invalid MLS Event ID"))?;
            let existing = sql_query("SELECT c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE e.id=$1")
                .bind::<Binary,_>(token.to_vec()).get_result::<CommitRow>(&mut *conn).await.optional()?;
            if let Some(existing) = existing {
                return Ok(arkret_wire::AuthoritySubmitOutcome::Accepted {
                    status: arkret_wire::AuthorityCommitStatus::Duplicate,
                    commit: decode_json(existing.commit_json, "original MLS Commit")?,
                });
            }
            if !same_authority(&current, authority) {
                return Err(PersistenceError::Conflict("temporarily_unavailable: MLS refusal authority changed".into()).into());
            }
            #[derive(QueryableByName)]
            struct RefusalRow {
                #[diesel(sql_type = Text)]
                rejection_reason: String,
            }
            sql_query("UPDATE canonical_events SET state='rejected',rejection_reason=$2 WHERE id=$1 AND state='queued'")
                .bind::<Binary,_>(token.to_vec()).bind::<Text,_>(reason_code)
                .execute(&mut *conn).await?;
            let refused = sql_query("SELECT rejection_reason FROM canonical_events WHERE id=$1 AND state='rejected'")
                .bind::<Binary,_>(token.to_vec()).get_result::<RefusalRow>(&mut *conn).await?;
            Ok(arkret_wire::AuthoritySubmitOutcome::Rejected {
                status: arkret_wire::AuthorityRejectionStatus::Rejected,
                reason_code: refused.rejection_reason,
            })
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn queued_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<QueuedEventRecord>> {
        let token = ids::parse_event_id(event_id.as_str())
            .ok_or_else(|| invalid("Event id is not a canonical Event token"))?;
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT e.envelope, e.state, e.received_at, e.rejection_reason, c.commit_json, \
                    f.status AS forward_status, f.reason_code AS forward_reason_code, \
                    f.attempted_at AS forward_attempted_at, \
                    f.original_submission_json AS forward_original_submission, f.accepted_commit_json AS forward_accepted_commit \
             FROM canonical_events e LEFT JOIN realm_commits c ON c.event_pk = e.pk \
             LEFT JOIN authority_forward_attempts f ON f.event_pk=e.pk \
             WHERE e.id = $1",
        )
        .bind::<Binary, _>(token.to_vec())
        .get_result::<EventRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| {
            let status = match row.state.as_str() {
                "queued" => QueuedEventStatus::Queued,
                "committed" => QueuedEventStatus::Committed,
                "rejected" => QueuedEventStatus::Rejected,
                other => {
                    return Err(PersistenceError::Internal(format!(
                        "stored Event has unknown queue state {other:?}"
                    )));
                }
            };
            Ok(QueuedEventRecord {
                event: decode_json(row.envelope, "queued Event")?,
                status,
                queued_at: row.received_at,
                committed: row
                    .commit_json
                    .map(|value| decode_json(value, "RealmCommit"))
                    .transpose()?,
                rejection_reason: row.rejection_reason,
                forward_attempt: match (row.forward_status, row.forward_attempted_at) {
                    (None, None) => None,
                    (Some(status), Some(attempted_at)) => Some(ForwardAttemptRecord {
                        original_submission: row
                            .forward_original_submission
                            .map(|v| decode_json(v, "forward original submission"))
                            .transpose()?,
                        accepted_commit: row
                            .forward_accepted_commit
                            .map(|v| decode_json(v, "forward accepted witness"))
                            .transpose()?,
                        status: match status.as_str() {
                            "forwarding" => ForwardAttemptStatus::Forwarding,
                            "rejected" => ForwardAttemptStatus::Rejected,
                            "temporarily_unavailable" => {
                                ForwardAttemptStatus::TemporarilyUnavailable
                            }
                            other => {
                                return Err(PersistenceError::Internal(format!(
                                    "stored forward attempt has unknown status {other:?}"
                                )));
                            }
                        },
                        reason_code: row.forward_reason_code,
                        attempted_at,
                    }),
                    _ => {
                        return Err(PersistenceError::Internal(
                            "stored forward attempt is incomplete".to_owned(),
                        ));
                    }
                },
            })
        })
        .transpose()
    }

    #[cfg(any(test, feature = "test-support"))]
    async fn admit_event_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome> {
        transaction.validate().map_err(invalid)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            queue_event_in_connection(conn, &transaction.event, queued_at).await?;
            let outcome = require_atomic_admission_outcome(
                commit_transaction_in_connection(conn, transaction).await?,
            )?;
            if matches!(outcome, AuthorityCommitWriteOutcome::Committed) {
                commit_capability_grant_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
                commit_mimi_room_binding_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
            }
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    #[cfg(any(test, feature = "test-support"))]
    async fn admit_self_event_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
        guard: &SelfProducerCommitGuard,
        queued_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome> {
        transaction.validate().map_err(invalid)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::realm_authorization_cut::lock_realm_authorization_cut(
                conn,
                &transaction.event.realm_id,
            )
            .await?;
            if is_exact_accepted_event_replay(conn, &transaction.event, &transaction.commit).await?
            {
                return Ok(AuthorityCommitWriteOutcome::Duplicate);
            }
            let prepared_human =
                crate::agent_producer_signer_keys::validate_prepared_local_human_in_connection(
                    conn,
                    transaction,
                )
                .await?;
            check_self_producer_guard_in_connection(
                conn,
                &transaction.event,
                guard,
                transaction.commit.committed_at,
            )
            .await?;
            queue_event_in_connection(conn, &transaction.event, queued_at).await?;
            let outcome = require_atomic_admission_outcome(
                commit_transaction_in_connection(conn, transaction).await?,
            )?;
            if matches!(outcome, AuthorityCommitWriteOutcome::Committed) {
                if let Some(fact) = prepared_human.as_ref() {
                    crate::agent_producer_signer_keys::retain_prepared_human_in_connection(
                        conn,
                        &transaction.event,
                        &transaction.commit,
                        fact,
                    )
                    .await?;
                    crate::account_device_committed_evidence::retain_from_guard(
                        conn,
                        &transaction.event,
                        &transaction.commit,
                        fact,
                        Some(guard),
                    )
                    .await?;
                } else {
                    crate::agent_producer_signer_keys::retain_in_connection(
                        conn,
                        &transaction.event,
                        &transaction.commit,
                        Some(guard),
                    )
                    .await?;
                }
                commit_capability_grant_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
                commit_mimi_room_binding_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
            }
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn commit_transaction(
        &self,
        transaction: &AuthorityCommitTransaction,
    ) -> PersistenceResult<AuthorityCommitWriteOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let outcome = commit_transaction_in_connection(conn, transaction).await?;
            if matches!(outcome, AuthorityCommitWriteOutcome::Committed) {
                commit_capability_grant_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
                commit_mimi_room_binding_current_result_in_connection(
                    conn,
                    &transaction.event,
                    &transaction.commit,
                )
                .await?;
            }
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn stream_head(
        &self,
        stream_ref: &arkret_wire::CommitStreamRef,
    ) -> PersistenceResult<Option<arkret_wire::CommitStreamHead>> {
        let key = stream_key(stream_ref)?;
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT stream_ref, stream_position, commit_id FROM realm_commits \
             WHERE stream_key = $1 ORDER BY stream_position DESC LIMIT 1",
        )
        .bind::<Text, _>(key)
        .get_result::<HeadRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| {
            Ok(arkret_wire::CommitStreamHead {
                stream_ref: decode_json(row.stream_ref, "commit stream ref")?,
                stream_position: to_u64(row.stream_position, "stream position")?,
                commit_id: decode_text(row.commit_id, "RealmCommit id")?,
            })
        })
        .transpose()
    }

    async fn committed_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<coland_storage::CommittedEventRecord>> {
        let token = ids::parse_event_id(event_id.as_str())
            .ok_or_else(|| invalid("committed Event lookup has malformed Event id"))?;
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT c.commit_json, e.envelope FROM realm_commits c \
             JOIN canonical_events e ON e.pk = c.event_pk \
             WHERE e.id = $1",
        )
        .bind::<Binary, _>(token.to_vec())
        .get_result::<CommitStreamRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| {
            let commit: arkret_wire::RealmCommit = decode_json(row.commit_json, "RealmCommit")?;
            let event: arkret_wire::Event = decode_json(row.envelope, "committed Event")?;
            if commit.event_ref != *event_id || event.event_id != *event_id {
                return Err(PersistenceError::Internal(
                    "durable committed Event pair disagrees with its lookup key".into(),
                ));
            }
            Ok(coland_storage::CommittedEventRecord { commit, event })
        })
        .transpose()
    }

    async fn committed_event_by_commit_id(
        &self,
        commit_id: &arkret_wire::RealmCommitId,
    ) -> PersistenceResult<Option<coland_storage::CommittedEventRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT c.commit_json, e.envelope FROM realm_commits c \
             JOIN canonical_events e ON e.pk = c.event_pk \
             WHERE c.commit_id = $1",
        )
        .bind::<Text, _>(commit_id.as_str())
        .get_result::<CommitStreamRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| {
            let commit: arkret_wire::RealmCommit = decode_json(row.commit_json, "RealmCommit")?;
            let event: arkret_wire::Event = decode_json(row.envelope, "committed Event")?;
            if commit.commit_id != *commit_id || commit.event_ref != event.event_id {
                return Err(PersistenceError::Internal(
                    "durable committed Event pair disagrees with its Commit id".into(),
                ));
            }
            Ok(coland_storage::CommittedEventRecord { commit, event })
        })
        .transpose()
    }

    async fn current_mimi_room_binding(
        &self,
        room_uri: &arkret_wire::MimiRoomUri,
    ) -> PersistenceResult<Option<coland_storage::MimiRoomBindingCurrentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        sql_query(
            "SELECT mimi_room_uri,realm_id,current_commit_id,current_stream_position,current_event_id,value \
             FROM mimi_room_binding_current_results WHERE mimi_room_uri=$1",
        )
        .bind::<Text, _>(room_uri.as_str())
        .get_result::<MimiRoomBindingCurrentRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(decode_mimi_room_binding_current)
        .transpose()
    }

    async fn agent_owner_direct_scope(
        &self,
        realm: &arkret_wire::RealmId,
        agent: &arkret_wire::AccountId,
        controller: &arkret_wire::AccountId,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool).await?;
        crate::agent_interaction_current_results::owner_direct_in_connection(
            &mut conn, realm, agent, controller,
        )
        .await
    }

    async fn current_agent_result(
        &self,
        realm_id: &arkret_wire::RealmId,
        selector: &arkret_wire::CurrentSelector,
    ) -> PersistenceResult<Option<arkret_wire::TypedCurrentRow>> {
        crate::agent_current_results::read_agent_current_result(&self.pool, realm_id, selector)
            .await
    }

    async fn realm_default_strand_current(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<arkret_wire::TypedCurrentRow>> {
        crate::realm_default_strand_current_results::read_current(&self.pool, realm_id).await
    }

    async fn signal_scope_authority(
        &self,
        query: coland_storage::SignalScopeAuthorityQuery<'_>,
    ) -> PersistenceResult<Option<coland_storage::SignalScopeAuthority>> {
        crate::signal_scope_authority::read(&self.pool, query).await
    }

    async fn signal_recipient_realms(
        &self,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Vec<arkret_wire::RealmId>> {
        crate::signal_scope_authority::recipient_realms(&self.pool, actor).await
    }

    async fn realm_stream_heads(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<coland_storage::RealmStreamCut>> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn)
                .await?;
            let Some(generation) =
                sql_query("SELECT generation FROM realm_authorities WHERE realm_id=$1")
                    .bind::<Text, _>(realm_id.as_str())
                    .get_result::<RealmGenerationRow>(&mut *conn)
                    .await
                    .optional()?
            else {
                return Ok(None);
            };
            let rows = sql_query(REALM_STREAM_HEADS_SQL)
                .bind::<Text, _>(realm_id.as_str())
                .load::<HeadRow>(&mut *conn)
                .await?;
            let mut stream_heads = rows
                .into_iter()
                .map(|row| {
                    Ok(arkret_wire::CommitStreamHead {
                        stream_ref: decode_json(row.stream_ref, "commit stream ref")?,
                        stream_position: to_u64(row.stream_position, "stream position")?,
                        commit_id: decode_text(row.commit_id, "RealmCommit id")?,
                    })
                })
                .collect::<PersistenceResult<Vec<_>>>()?;
            stream_heads.sort_by(|left, right| left.stream_ref.cmp(&right.stream_ref));
            Ok(Some(coland_storage::RealmStreamCut {
                governance_generation: to_u64(generation.generation, "governance generation")?,
                stream_heads,
            }))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn accepted_realm_links(
        &self,
        realm: &arkret_wire::RealmId,
        direction: arkret_models_collaboration::governance::realm_governance::RealmLinkDirection,
        allow: Option<&[String]>,
    ) -> PersistenceResult<
        Vec<arkret_models_collaboration::governance::realm_governance::RealmLinkEntry>,
    > {
        crate::object_projection_reads::realm_link_list(&self.pool, realm, direction, allow).await
    }

    async fn accepted_realm_organization_read(
        &self, realm: &arkret_wire::RealmId, caller: &arkret_wire::ActorId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<arkret_models_collaboration::governance::realm_governance::RealmOrganizationRelationshipList>>{
        crate::object_projection_reads::realm_organization_read(&self.pool, realm, caller, at).await
    }

    async fn realm_state_snapshot_material(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<coland_storage::RealmStateSnapshotMaterial>> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn)
                .await?;
            realm_state_snapshot_material_in_connection(conn, realm_id)
                .await
                .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn sidecar_participant_authority_cut(
        &self,
        realm_id: &arkret_wire::RealmId,
        sidecar_id: &arkret_wire::SidecarId,
        controller: &arkret_wire::AccountId,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::agent_sidecar::SidecarParticipantAuthorityCut>,
    > {
        crate::sidecar_authority_cut::read(&self.pool, realm_id, sidecar_id, controller).await
    }

    async fn realm_state_snapshot_material_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<coland_storage::RealmStateSnapshotMaterial>> {
        crate::snapshot_disclosure_gate::account_snapshot_material(&self.pool, realm_id, account)
            .await
    }

    async fn account_continuation_heads_covered(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        minimum_heads: &[arkret_wire::CommitStreamHead],
    ) -> PersistenceResult<bool> {
        crate::snapshot_disclosure_gate::account_continuation_heads_covered(
            &self.pool,
            realm_id,
            account,
            minimum_heads,
        )
        .await
    }

    async fn direct_conversation_replica_cut(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        pair_key: &arkret_wire::Hash,
        participants: &[arkret_wire::ActorId; 2],
    ) -> PersistenceResult<Option<coland_storage::DirectConversationReplicaCut>> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn)
                .await?;
            let caller = arkret_wire::ActorId::account(account.clone());
            if participants[0] == participants[1]
                || !participants.contains(&caller)
                || crate::account_stream_scan::snapshot_realm_floor_in_connection(
                    conn, realm_id, &caller,
                )
                .await?
                .is_none()
            {
                return Ok(None);
            }
            let Some(authority) = sql_query(
                "SELECT realm_id, generation, service_id, authority_ref, last_handoff_ref \
                 FROM realm_authorities WHERE realm_id=$1",
            )
            .bind::<Text, _>(realm_id.as_str())
            .get_result::<AuthorityRow>(&mut *conn)
            .await
            .optional()?
            .map(authority_from_row)
            .transpose()?
            else {
                return Ok(None);
            };
            let Some((head, entries)) = crate::replica_authorization::direct_current_evidence(
                conn,
                realm_id,
                pair_key,
                participants,
            )
            .await?
            else {
                return Ok(None);
            };
            Ok(Some(coland_storage::DirectConversationReplicaCut {
                authority,
                head,
                current_state_entries: entries,
            }))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn sidecar_context_prepare_current(
        &self,
        realm: &arkret_wire::RealmId,
        controller: &arkret_wire::AccountId,
        context: &arkret_models_collaboration::sidecar_operations::SidecarContextRef,
    ) -> PersistenceResult<
        Option<(
            arkret_wire::EventId,
            Option<coland_storage::AgentSidecarContextRecord>,
        )>,
    > {
        crate::sidecar_current_results::prepare_context_current(
            &self.pool, realm, controller, context,
        )
        .await
    }

    async fn sidecar_access_cut(
        &self,
        realm: &arkret_wire::RealmId,
        sidecar: &arkret_wire::SidecarId,
        controller: &arkret_wire::AccountId,
        device: &arkret_wire::DeviceId,
    ) -> PersistenceResult<
        Option<(
            arkret_models_collaboration::agent_sidecar::SidecarParticipantAuthorityCut,
            Vec<arkret_wire::DidCoreId>,
            Option<arkret_wire::MlsGroupCurrent>,
            bool,
        )>,
    > {
        crate::sidecar_authority_cut::read_access(&self.pool, realm, sidecar, controller, device)
            .await
    }

    async fn object_projection_lists_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
        include_terminal: bool,
    ) -> PersistenceResult<
        Option<(
            arkret_models_collaboration::objects::query_projection::ProjectionSpaceList,
            arkret_models_collaboration::objects::query_projection::ProjectionStrandList,
        )>,
    > {
        crate::object_projection_reads::lists_for_actor(
            &self.pool,
            realm_id,
            actor,
            include_terminal,
        )
        .await
    }

    async fn object_projection_delivery_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
        include_terminal: bool,
    ) -> PersistenceResult<
        Option<(
            arkret_models_collaboration::objects::query_projection::ProjectionSpaceList,
            arkret_models_collaboration::objects::query_projection::ProjectionStrandList,
            arkret_models_collaboration::sync_frames::current_results::AccountCurrentView,
        )>,
    > {
        crate::object_projection_reads::delivery_for_actor(
            &self.pool,
            realm_id,
            actor,
            include_terminal,
        )
        .await
    }

    async fn morph_list_for_actor(
        &self,
        realm: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
        station: &arkret_wire::DidCoreId,
        include_terminal: bool,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::objects::query_projection::ProjectionMorphList>,
    > {
        crate::morph_projection_reads::list_for_actor(
            &self.pool,
            realm,
            actor,
            station,
            include_terminal,
        )
        .await
    }

    async fn document_morph_for_actor(
        &self,
        realm: &arkret_wire::RealmId,
        morph: &arkret_wire::MorphId,
        actor: &arkret_wire::ActorId,
        station: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        Option<
            arkret_models_collaboration::objects::query_projection::DocumentMorphProjectionOutcome,
        >,
    > {
        crate::morph_projection_reads::document_for_actor(&self.pool, realm, morph, actor, station)
            .await
    }

    async fn realm_export_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        actor: &arkret_wire::ActorId,
        station: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        Option<(
            arkret_models_collaboration::governance::realm_governance::RealmExport,
            Vec<arkret_wire::CommittedEventView>,
        )>,
    > {
        crate::account_content_delivery::realm_export_for_actor(
            &self.pool, realm_id, actor, station,
        )
        .await
    }

    async fn visible_strand_scope_for_actor(
        &self,
        realm_id: &arkret_wire::RealmId,
        strand_id: &arkret_wire::StrandId,
        actor: &arkret_wire::ActorId,
    ) -> PersistenceResult<Option<arkret_wire::ScopeRef>> {
        crate::object_projection_reads::visible_strand_scope_for_actor(
            &self.pool, realm_id, strand_id, actor,
        )
        .await
    }

    async fn member_station_bootstrap_material(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        membership_commit_id: &arkret_wire::RealmCommitId,
    ) -> PersistenceResult<Option<coland_storage::RealmStateSnapshotMaterial>> {
        crate::snapshot_disclosure_gate::member_station_bootstrap_material(
            &self.pool,
            realm_id,
            account,
            membership_commit_id,
        )
        .await
    }

    async fn member_station_bootstrap_floor(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        membership_commit_id: &arkret_wire::RealmCommitId,
    ) -> PersistenceResult<Option<u64>> {
        crate::snapshot_disclosure_gate::member_station_bootstrap_floor(
            &self.pool,
            realm_id,
            account,
            membership_commit_id,
        )
        .await
    }

    async fn issue_realm_state_snapshot_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
        sign: coland_storage::RealmStateSnapshotSigner<'_>,
    ) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
        crate::snapshot_disclosure_gate::issue_account_snapshot(
            &self.pool, realm_id, account, issuer, sign,
        )
        .await
    }

    async fn install_verified_account_snapshot(
        &self,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
        snapshot: &arkret_wire::RealmStateSnapshot,
    ) -> PersistenceResult<()> {
        crate::issued_realm_snapshots::install_verified_account_snapshot(
            &self.pool, account, issuer, snapshot,
        )
        .await
    }

    async fn issued_realm_state_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        snapshot_id: &arkret_wire::RealmSnapshotId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
        crate::issued_realm_snapshots::PgIssuedRealmSnapshotArchive::new(self.pool.clone())
            .by_ref(account, realm_id, snapshot_id, issuer)
            .await
    }

    async fn freeze_account_realm_window(
        &self,
        request: &coland_storage::AccountRealmWindowRequest,
        sign: coland_storage::RealmStateSnapshotSigner<'_>,
    ) -> PersistenceResult<Option<coland_storage::AccountRealmWindow>> {
        crate::issued_realm_snapshots::freeze_account_realm_window(&self.pool, request, sign).await
    }

    async fn account_window_basis(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        window_cursor: &str,
        stream_ref: &arkret_wire::CommitStreamRef,
        issuer: &arkret_wire::DidCoreId,
        now_ms: i64,
    ) -> PersistenceResult<
        Option<arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis>,
    > {
        crate::issued_realm_snapshots::account_window_basis(
            &self.pool,
            realm_id,
            account,
            window_cursor,
            stream_ref,
            issuer,
            now_ms,
        )
        .await
    }

    async fn scan_stream(
        &self,
        request: &arkret_wire::StreamScanRequest,
    ) -> PersistenceResult<arkret_wire::StreamScanOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        stream_page_in_connection(&mut conn, request).await
    }

    async fn scan_stream_for_account(
        &self,
        request: &arkret_wire::StreamScanRequest,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<coland_storage::AccountStreamScan> {
        crate::account_stream_scan::scan_stream_for_account(&self.pool, request, account, issuer)
            .await
    }

    async fn committed_event_for_peer(
        &self,
        event_id: &arkret_wire::EventId,
        peer: &arkret_wire::DidCoreId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<Option<arkret_wire::CommittedEventFullView>> {
        crate::account_stream_scan::committed_event_for_peer(&self.pool, event_id, peer, issuer)
            .await
    }

    async fn committed_event_for_member(
        &self,
        event_id: &arkret_wire::EventId,
        caller: &arkret_wire::ActorId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<coland_storage::MemberCommittedEventRead> {
        crate::account_stream_scan::committed_event_for_member(&self.pool, event_id, caller, issuer)
            .await
    }

    async fn scan_stream_for_peer(
        &self,
        request: &arkret_wire::StreamScanRequest,
        peer: &arkret_wire::DidCoreId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<coland_storage::PeerStreamScan> {
        crate::account_stream_scan::scan_stream_for_peer(&self.pool, request, peer, issuer).await
    }

    async fn list_realm_streams_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<coland_storage::AccountRealmStreamList> {
        crate::self_current_reads::list_realm_streams_for_account(
            &self.pool, realm_id, account, issuer,
        )
        .await
    }

    async fn realm_stream_subscription_cut(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<coland_storage::AccountRealmStreamAuthorizationCut> {
        crate::self_current_reads::realm_stream_subscription_cut(
            &self.pool, realm_id, account, issuer,
        )
        .await
    }

    async fn exact_current_result_for_account(
        &self,
        request: &arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadRequestBody,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        coland_storage::SelfExactCurrentRead<
            arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome,
        >,
    > {
        crate::self_current_reads::exact_current_result_for_account(
            &self.pool, request, account, issuer,
        )
        .await
    }

    async fn strand_watch_current_for_account(
        &self,
        request: &arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentRequestBody,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<
        coland_storage::SelfExactCurrentRead<
            arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentOutcome,
        >,
    > {
        crate::self_current_reads::strand_watch_current_for_account(
            &self.pool, request, account, issuer,
        )
        .await
    }

    async fn media_service_anchor_for_account(
        &self,
        realm_id: &arkret_wire::RealmId,
        account: &arkret_wire::AccountId,
        issuer: &arkret_wire::DidCoreId,
    ) -> PersistenceResult<coland_storage::MediaServiceAnchorRead> {
        crate::self_current_reads::media_service_anchor_for_account(
            &self.pool, realm_id, account, issuer,
        )
        .await
    }

    async fn handoff_originals(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<arkret_wire::CommittedEventFullView>> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn)
                .await?;
            Ok(handoff_originals_in_connection(conn, realm_id).await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn install_handoff(
        &self,
        handoff: &arkret_wire::RealmAuthorityHandoff,
        final_stream_heads: &[arkret_wire::CommitStreamHead],
        snapshot: &arkret_wire::RealmStateSnapshot,
    ) -> PersistenceResult<()> {
        handoff.validate_shape().map_err(invalid)?;
        verify_snapshot_content_id(snapshot)?;
        if final_stream_heads.is_empty()
            || !final_stream_heads
                .windows(2)
                .all(|pair| pair[0].stream_ref < pair[1].stream_ref)
            || final_stream_heads
                .iter()
                .any(|head| head.stream_ref.realm_id() != &handoff.realm_id)
        {
            return Err(invalid(
                "handoff stream heads must be non-empty, sorted, unique, and same-Realm",
            ));
        }
        let heads_digest = arkret_identifiers::Hash::new(
            arkret_canonical::canonical_sha256(&final_stream_heads)
                .map_err(PersistenceError::database)?,
        )
        .map_err(invalid)?;
        if heads_digest != handoff.final_stream_heads_digest
            || snapshot.snapshot_id != handoff.snapshot_ref
            || snapshot.realm_id != handoff.realm_id
            || snapshot.governance_generation != handoff.from_generation
            || snapshot.visible_stream_heads != final_stream_heads
            || snapshot.signature.context != arkret_wire::DetachedSignatureContext::RealmSnapshot
            || signature_service_id(&snapshot.signature)? != handoff.from_service_id
        {
            return Err(invalid("handoff snapshot or stream-head binding mismatch"));
        }
        let snapshot_json = serde_json::to_value(snapshot).map_err(PersistenceError::database)?;
        let handoff_json = serde_json::to_value(handoff).map_err(PersistenceError::database)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let current = locked_authority(conn, &handoff.realm_id)
                .await?
                .ok_or_else(|| PersistenceError::NotFound("Realm authority not initialized".into()))?;
            if current.generation == handoff.to_generation
                && current.service_id == handoff.to_service_id
                && current.last_handoff_ref.as_ref() == Some(&handoff.handoff_id)
            {
                let held = sql_query("SELECT handoff_json FROM realm_authority_handoffs WHERE handoff_id=$1")
                    .bind::<Text,_>(handoff.handoff_id.as_str()).get_result::<HandoffRow>(&mut *conn).await?;
                let held_snapshot = sql_query("SELECT snapshot_json FROM realm_state_snapshots WHERE snapshot_id=$1")
                    .bind::<Text,_>(snapshot.snapshot_id.as_str()).get_result::<SnapshotRow>(&mut *conn).await?;
                if held.handoff_json != handoff_json || held_snapshot.snapshot_json != snapshot_json {
                    return Err(invalid("handoff replay differs from the installed original").into());
                }
                return Ok(());
            }
            if current.generation != handoff.from_generation
                || current.service_id != handoff.from_service_id
            {
                return Err(PersistenceError::Conflict("failed_precondition: stale Realm authority handoff".into()).into());
            }

            let rows = sql_query(
                REALM_STREAM_HEADS_SQL,
            )
            .bind::<Text, _>(handoff.realm_id.as_str())
            .load::<HeadRow>(&mut *conn)
            .await?;
            let mut stored_heads = rows
                .into_iter()
                .map(|row| {
                    Ok(arkret_wire::CommitStreamHead {
                        stream_ref: decode_json(row.stream_ref, "commit stream ref")?,
                        stream_position: to_u64(row.stream_position, "stream position")?,
                        commit_id: decode_text(row.commit_id, "RealmCommit id")?,
                    })
                })
                .collect::<PersistenceResult<Vec<_>>>()?;
            stored_heads.sort_by(|left, right| left.stream_ref.cmp(&right.stream_ref));
            if stored_heads != final_stream_heads {
                return Err(PersistenceError::Conflict(
                    "failed_precondition: handoff final stream heads do not match durable stream tails".into(),
                )
                .into());
            }
            let realm_head = final_stream_heads.iter().find(|head| {
                head.stream_ref
                    == arkret_wire::CommitStreamRef::Realm {
                        realm_id: handoff.realm_id.clone(),
                    }
            });
            if realm_head.map(|head| &head.commit_id) != Some(&handoff.change_commit_id) {
                return Err(invalid("handoff change commit is not the final Realm stream head").into());
            }

            // The endpoint activates a pre-imported frozen state. A readable
            // member suffix or an inline current-only snapshot is insufficient.
            let originals = handoff_originals_in_connection(conn, &handoff.realm_id).await?;
            let change = originals.iter().find(|full| full.commit.commit_id == handoff.change_commit_id)
                .ok_or_else(|| invalid("handoff change original is not held"))?;
            if change.event.event_id != handoff.change_event_ref
                || change.event.kind != arkret_wire::EventKind::RealmGovernanceStationChange
                || change.commit.governance_generation != handoff.from_generation {
                return Err(invalid("handoff does not bind the outgoing committed change Event").into());
            }
            let payload: arkret_models_collaboration::events_payloads::RealmGovernanceStationChangePayload =
                serde_json::from_value(serde_json::to_value(&change.event.payload).map_err(PersistenceError::database)?).map_err(invalid)?;
            if payload.expected_governance_generation != handoff.from_generation
                || payload.new_governance_station_id != handoff.to_service_id
                || Some(&payload.expected_realm_stream_commit_id) != change.commit.previous_commit_ref.as_ref() {
                return Err(invalid("handoff differs from the accepted change CAS").into());
            }
            let mut watch_cells = std::collections::BTreeSet::new();
            for full in &originals {
                if full.event.kind == arkret_wire::EventKind::StrandWatchSet {
                    let payload: arkret_models_collaboration::events_payloads::strand::StrandWatchSetPayload = serde_json::from_value(
                        serde_json::to_value(&full.event.payload).map_err(PersistenceError::database)?
                    ).map_err(PersistenceError::database)?;
                    watch_cells.insert((full.commit.stream_ref.clone(), payload.strand_id, payload.watcher_actor_id));
                }
            }
            for row in &snapshot.current_state_entries {
                let arkret_wire::TypedCurrentRow::Value { selector, source_stream_ref, .. } = row;
                if let arkret_wire::CurrentSelector::StrandWatch { strand_id, watcher_actor_id } = selector {
                    watch_cells.insert((source_stream_ref.clone(), strand_id.clone(), watcher_actor_id.clone()));
                }
            }
            for (stream, strand, actor) in watch_cells {
                let head = final_stream_heads.iter().find(|head| head.stream_ref == stream)
                    .ok_or_else(|| invalid("handoff Watch namespace has no final head"))?;
                crate::strand_watch_current_results::require_current_basis_in_connection(
                    conn, &handoff.realm_id, head, &strand, &actor, ""
                ).await?;
            }
            let inventory = handoff_inventory_in_connection(conn, &originals).await?;
            let digest = arkret_models_collaboration::authority_commit::historical_signer_facts_digest(&inventory).map_err(invalid)?;
            if handoff.historical_signer_facts_digest.as_ref() != Some(&digest) {
                return Err(invalid("handoff requires the complete imported signer fact inventory").into());
            }
            let material = realm_state_snapshot_material_in_connection(conn, &handoff.realm_id).await?
                .ok_or_else(|| invalid("handoff typed current is not imported"))?;
            if !coland_storage::signed_snapshot_matches_material(snapshot, &material) {
                return Err(invalid("handoff Snapshot differs from the complete imported current and floors").into());
            }

            sql_query(
                "INSERT INTO realm_state_snapshots \
                 (snapshot_id, realm_id, governance_generation, snapshot_json, created_at) \
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (snapshot_id) DO NOTHING",
            )
            .bind::<Text, _>(snapshot.snapshot_id.as_str())
            .bind::<Text, _>(snapshot.realm_id.as_str())
            .bind::<BigInt, _>(to_i64(snapshot.governance_generation, "snapshot governance generation")?)
            .bind::<Jsonb, _>(&snapshot_json)
            .bind::<Timestamptz, _>(snapshot.created_at)
            .execute(&mut *conn)
            .await?;
            sql_query(
                "INSERT INTO realm_authority_handoffs \
                 (handoff_id, realm_id, from_generation, to_generation, from_service_id, to_service_id, handoff_json) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind::<Text, _>(handoff.handoff_id.as_str())
            .bind::<Text, _>(handoff.realm_id.as_str())
            .bind::<BigInt, _>(to_i64(handoff.from_generation, "handoff from_generation")?)
            .bind::<BigInt, _>(to_i64(handoff.to_generation, "handoff to_generation")?)
            .bind::<Text, _>(handoff.from_service_id.as_str())
            .bind::<Text, _>(handoff.to_service_id.as_str())
            .bind::<Jsonb, _>(&handoff_json)
            .execute(&mut *conn)
            .await?;
            sql_query(
                "UPDATE realm_authorities SET generation = $2, service_id = $3, \
                 authority_ref = $4, last_handoff_ref = $5, updated_at = now() WHERE realm_id = $1",
            )
            .bind::<Text, _>(handoff.realm_id.as_str())
            .bind::<BigInt, _>(to_i64(handoff.to_generation, "handoff to_generation")?)
            .bind::<Text, _>(handoff.to_service_id.as_str())
            .bind::<Jsonb, _>(serde_json::to_value(arkret_wire::RealmCommitAuthorityRef::Handoff(handoff.handoff_id.clone())).map_err(PersistenceError::database)?)
            .bind::<Text, _>(handoff.handoff_id.as_str())
            .execute(&mut *conn)
            .await?;
            Ok(())
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn authority_handoffs(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Vec<arkret_wire::RealmAuthorityHandoff>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT handoff_json FROM realm_authority_handoffs WHERE realm_id = $1 \
             ORDER BY to_generation ASC",
        )
        .bind::<Text, _>(realm_id.as_str())
        .load::<HandoffRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| decode_json(row.handoff_json, "Realm authority handoff"))
            .collect()
    }

    async fn latest_snapshot(
        &self,
        realm_id: &arkret_wire::RealmId,
    ) -> PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query(
            "SELECT snapshot_json FROM realm_state_snapshots snapshot WHERE realm_id = $1 \
             AND NOT EXISTS (SELECT 1 FROM realm_state_snapshot_issuances issued \
                             WHERE issued.snapshot_id = snapshot.snapshot_id) \
             ORDER BY governance_generation DESC, created_at DESC LIMIT 1",
        )
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<SnapshotRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        row.map(|row| decode_json(row.snapshot_json, "RealmStateSnapshot"))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_authority_is_an_atomic_admission_rollback_error() {
        let realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x61; 32],
        ));
        let authority = CurrentRealmAuthority {
            realm_id,
            generation: 2,
            service_id: arkret_wire::DidCoreId::new("ak:did_core:web:station.example".to_owned())
                .unwrap(),
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [0x62; 32],
                ),
            ),
            last_handoff_ref: None,
        };
        assert!(
            require_atomic_admission_outcome(AuthorityCommitWriteOutcome::StaleAuthority(
                authority
            ))
            .is_err(),
            "returning Ok(StaleAuthority) would commit the preceding queue insert"
        );
        assert!(matches!(
            require_atomic_admission_outcome(AuthorityCommitWriteOutcome::Committed),
            Ok(AuthorityCommitWriteOutcome::Committed)
        ));
        assert!(matches!(
            require_atomic_admission_outcome(AuthorityCommitWriteOutcome::Duplicate),
            Ok(AuthorityCommitWriteOutcome::Duplicate)
        ));
    }

    #[test]
    fn duplicate_event_accepts_only_the_exact_realm_commit() {
        let existing = serde_json::json!({
            "commit_id":"ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "stream_position":7,
            "committed_at":"2026-09-21T00:00:00Z"
        });
        assert!(require_exact_commit_replay(&existing, &existing).is_ok());

        let divergent = serde_json::json!({
            "commit_id":"ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "stream_position":7,
            "committed_at":"2026-09-21T00:00:01Z"
        });
        assert!(matches!(
            require_exact_commit_replay(&existing, &divergent),
            Err(PersistenceError::Conflict(reason))
                if reason.starts_with("duplicate_conflict:")
        ));
    }

    #[test]
    fn mimi_migration_topology_preserves_optional_field_presence() {
        let absent = serde_json::json!({
            "hub_provider_id": "ak:did_core:web:hub.example",
            "local_provider_role": "hub"
        });
        let present_empty_followers = serde_json::json!({
            "hub_provider_id": "ak:did_core:web:hub.example",
            "local_provider_role": "hub",
            "follower_provider_ids": []
        });
        assert!(!mimi_migration_topology_matches(
            &absent,
            &present_empty_followers
        ));
        assert!(mimi_migration_topology_matches(&absent, &absent));
        assert_eq!(
            invalid_mimi_migration().conflict_code(),
            Some(coland_storage::ConflictCode::MimiRoomBindingMigrationProofInvalid)
        );
    }
}
