//! Caller-scoped `ak.self.committed_event.read.scan.v1` and
//! `ak.peer.committed_event.read.scan.v1` at one read cut.
//!
//! The caller's readable interval is a protocol decision of the current
//! governing Station: membership join floor, history-access policy, retention
//! and per-Event disclosure all bound it. This Station proves the Realm
//! stream interval of a currently joined member from its join Commit or the
//! genesis Commit ([`caller_realm_floor_in_connection`]). Within it each row
//! is served in full or, when the member committed-event disclosure decision
//! withholds its Event, as the withheld branch on the same Commit. Any other
//! shape fails closed as unproved rather than serving a physical page.
//!
//! A member Station serves its own hosted members from the Realm stream it
//! holds as an anchored replica (`federation.md` §4.1.1): the interval starts
//! at the member's own join under `since_join`, and a history this Station
//! does not hold is unproved. A chain node is served as the withheld branch.
//!
//! A peer Station's replication right on a stream derives from the members
//! routed to it (`federation.md` §4.1.1): from each currently joined member's
//! readable floor to the head, and for a member whose leave or ban ended its
//! joined state, from its readable floor through that terminating Commit.
//! A page stops before the first position outside every interval. Within
//! them each row is served in full only when that Station may hold the
//! Event's complete canonical bytes; a row withheld from that Station keeps
//! only its Commit, so the page stays one verifiable chain.

use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CommittedEventView, DidCoreId, ReadableFloor,
    ReadableFloorReason, StreamScanRequestBody, StreamScanResponseBody,
};
use coland_storage::AccountStreamScan;

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Bool, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, pg_conn,
    sql_query,
};

#[derive(QueryableByName)]
struct TenureRow {
    #[diesel(sql_type = Text)]
    service_id: String,
}

#[derive(QueryableByName)]
struct MemberRow {
    #[diesel(sql_type = Text)]
    member_id: String,
    #[diesel(sql_type = Text)]
    membership: String,
}

pub(crate) async fn scan_stream_for_actor(
    pool: &PgPool,
    request: &StreamScanRequestBody,
    actor: &ActorId,
    issuer: &DidCoreId,
) -> PersistenceResult<AccountStreamScan> {
    request
        .validate()
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        scan_stream_for_actor_in_connection(conn, request, actor, issuer).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn scan_stream_for_account(
    pool: &PgPool,
    request: &StreamScanRequestBody,
    account: &AccountId,
    issuer: &DidCoreId,
) -> PersistenceResult<AccountStreamScan> {
    request
        .validate()
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        scan_stream_for_account_in_connection(conn, request, account, issuer).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn scan_stream_for_account_in_connection(
    conn: &mut AsyncPgConnection,
    request: &StreamScanRequestBody,
    account: &AccountId,
    issuer: &DidCoreId,
) -> Result<AccountStreamScan, PgTransactionError> {
    scan_stream_for_actor_in_connection(conn, request, &ActorId::account(account.clone()), issuer)
        .await
}

pub(crate) async fn scan_stream_for_actor_in_connection(
    conn: &mut AsyncPgConnection,
    request: &StreamScanRequestBody,
    actor: &ActorId,
    issuer: &DidCoreId,
) -> Result<AccountStreamScan, PgTransactionError> {
    request
        .validate()
        .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
    let caller = actor.clone().to_string();
    let Some(tenure) = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(request.realm_id.as_str())
        .get_result::<TenureRow>(&mut *conn)
        .await
        .optional()?
    else {
        return Ok(AccountStreamScan::NotAuthorized);
    };
    if actor.as_realm_actor_id().is_some_and(|subject| {
        subject.realm_id != request.realm_id || tenure.service_id != issuer.as_str()
    }) {
        return Ok(AccountStreamScan::NotAuthorized);
    }
    let members = sql_query(
        "SELECT member_id, membership FROM member_state_current_states \
         WHERE realm_id=$1 ORDER BY member_id",
    )
    .bind::<Text, _>(request.realm_id.as_str())
    .load::<MemberRow>(&mut *conn)
    .await?;
    if !members
        .iter()
        .any(|row| row.member_id == caller && row.membership == "join")
    {
        return Ok(AccountStreamScan::NotAuthorized);
    }
    let caller_actor = actor.clone();
    let floor = match (&request.stream_ref, tenure.service_id == issuer.as_str()) {
        (CommitStreamRef::RealmControl { .. }, _) => return Ok(AccountStreamScan::NotAuthorized),
        (CommitStreamRef::Realm { .. }, true) => {
            caller_realm_floor_in_connection(conn, &request.realm_id, &caller_actor).await?
        }
        (CommitStreamRef::Circle { circle_id, .. }, true) => {
            caller_circle_floor_in_connection(conn, &request.realm_id, circle_id, &caller_actor)
                .await?
        }
        (CommitStreamRef::Sidecar { sidecar_id, .. }, true) => {
            crate::sidecar_authority_cut::public_material_floor_in_connection(
                conn,
                &request.realm_id,
                sidecar_id,
                &caller_actor,
            )
            .await?
        }
        (CommitStreamRef::Realm { .. }, false) => {
            match replica_realm_floor_in_connection(conn, &request.realm_id, &caller_actor).await? {
                Ok(floor) => Some(floor),
                Err(reason) => return Ok(AccountStreamScan::Unproved(reason)),
            }
        }
        (CommitStreamRef::Circle { circle_id, .. }, false) => {
            match replica_circle_floor_in_connection(
                conn,
                &request.realm_id,
                circle_id,
                &caller_actor,
            )
            .await?
            {
                Ok(floor) => Some(floor),
                Err(reason) => return Ok(AccountStreamScan::Unproved(reason)),
            }
        }
        (CommitStreamRef::Sidecar { sidecar_id, .. }, false) => {
            match crate::sidecar_replica_authority::handshake_floor_in_connection(
                conn,
                &request.realm_id,
                sidecar_id,
                &caller_actor,
            )
            .await?
            {
                Ok(floor) => floor,
                Err(reason) => return Ok(AccountStreamScan::Unproved(reason)),
            }
        }
        _ => {
            return Ok(AccountStreamScan::Unproved(
                "the requested stream has no proved disclosure rule",
            ));
        }
    };
    let Some(floor) = floor else {
        if matches!(
            request.stream_ref,
            CommitStreamRef::Circle { .. } | CommitStreamRef::Sidecar { .. }
        ) {
            return Ok(AccountStreamScan::NotAuthorized);
        }
        return Ok(AccountStreamScan::Unproved(
            "the caller's join or history floor is not proved at this cut",
        ));
    };
    let page =
        crate::authority_commit::stream_page_above_floor_in_connection(conn, request, Some(floor))
            .await?;
    // Per-Event disclosure applies on top of the interval: a withheld row
    // keeps its Commit so the page stays one verifiable chain.
    let committed_events =
        disclose_page_to_member(conn, page.committed_events.clone(), &caller_actor).await?;
    Ok(AccountStreamScan::Page(StreamScanResponseBody {
        committed_events,
        ..page
    }))
}

#[derive(QueryableByName)]
struct JoinRow {
    #[diesel(sql_type = Text)]
    membership: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

#[derive(QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

/// Apply the member committed-event disclosure decision to the full rows of
/// one page, keeping every Commit and the page order.
async fn disclose_page_to_member(
    conn: &mut AsyncPgConnection,
    items: Vec<CommittedEventView>,
    caller: &ActorId,
) -> PersistenceResult<Vec<CommittedEventView>> {
    let full = items
        .iter()
        .filter_map(|item| match item {
            CommittedEventView::Full(view) => Some(view.clone()),
            CommittedEventView::Withheld(_) => None,
        })
        .collect::<Vec<_>>();
    let mut disclosed =
        crate::committed_disclosure::disclose_to_member_in_connection(conn, full, caller)
            .await?
            .into_iter();
    items
        .into_iter()
        .map(|item| match item {
            CommittedEventView::Full(_) => disclosed.next().ok_or_else(|| {
                PersistenceError::Internal("member disclosure dropped a row".to_owned())
            }),
            withheld @ CommittedEventView::Withheld(_) => Ok(withheld),
        })
        .collect()
}

async fn realm_history_access(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<String>> {
    Ok(sql_query(
        "SELECT value FROM realm_bootstrap_current_states \
         WHERE realm_id=$1 AND state_family='realm_history_access'",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<ValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .and_then(|row| row.value.as_str().map(ToOwned::to_owned)))
}

pub(crate) async fn realm_purpose(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<arkret_models_collaboration::events_payloads::realm::RealmPurpose>> {
    let row = sql_query(
        "SELECT value->'purpose' AS value FROM realm_bootstrap_current_states \
         WHERE realm_id=$1 AND state_family='realm_genesis'",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<ValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    row.map(|row| {
        serde_json::from_value(row.value).map_err(|error| {
            PersistenceError::Internal(format!("stored Realm purpose is invalid: {error}"))
        })
    })
    .transpose()
}

/// The genesis readable floor of the Realm stream this governing Station
/// holds from position 0.
async fn genesis_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<ReadableFloor>> {
    Ok(crate::authority_commit::stream_page_in_connection(
        conn,
        &StreamScanRequestBody {
            realm_id: realm_id.clone(),
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            direction: arkret_wire::StreamScanDirection::After(None),
            limit: 1,
        },
    )
    .await?
    .readable_floor)
}

/// A replica may legitimately hold only a since-join suffix. Probe its exact
/// position zero without requiring that suffix to be a complete physical stream.
async fn held_genesis_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<ReadableFloor>> {
    let stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let row = sql_query(
        "SELECT commit_json FROM realm_commits \
         WHERE realm_id=$1 AND stream_key=$2 AND stream_position=0",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(crate::authority_commit::stream_key(&stream)?)
    .get_result::<ChainNodeRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    row.map(|row| {
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(row.commit_json).map_err(|error| {
                PersistenceError::Internal(format!("stored genesis Commit is invalid: {error}"))
            })?;
        if commit.realm_id != *realm_id
            || commit.stream_ref != stream
            || commit.stream_position != 0
            || commit.previous_commit_ref.is_some()
        {
            return Err(PersistenceError::SchemaViolation(
                "held genesis Commit differs from its exact Realm stream start".into(),
            ));
        }
        Ok(ReadableFloor {
            oldest_position: 0,
            floor_commit_id: commit.commit_id,
            floor_reason: ReadableFloorReason::StreamStart,
        })
    })
    .transpose()
}

/// The readable floor a member joined by the Commit `join_commit_id` at
/// `join_position` has on the Realm stream (`history-visibility.md` §3.1,
/// decision 0108 §1045), or `None` when it is not provable here.
///
/// Under `all_history_for_current_members` a joined member reads from the
/// genesis Commit. Under `since_join` the floor is the join Commit itself
/// (`membership_join`), unless that join was accepted in the same atomic
/// bootstrap or Direct Conversation founding unit as position 0, whose floor is
/// the genesis Commit (`stream_start`).
async fn join_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    genesis_floor: &ReadableFloor,
    join_commit_id: &str,
    join_position: i64,
) -> PersistenceResult<Option<ReadableFloor>> {
    match realm_history_access(conn, realm_id).await?.as_deref() {
        Some("all_history_for_current_members") => return Ok(Some(genesis_floor.clone())),
        Some("since_join") => {}
        _ => return Ok(None),
    }
    let founding = sql_query(
        "SELECT EXISTS (SELECT 1 FROM ordinary_realm_bootstrap_units u \
         CROSS JOIN LATERAL jsonb_array_elements(u.commits_json) c \
         WHERE u.realm_id=$1 AND c->>'commit_id'=$2) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(join_commit_id)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if founding.present {
        return Ok(Some(genesis_floor.clone()));
    }
    if direct_founding_join_in_connection(
        conn,
        realm_id,
        genesis_floor,
        join_commit_id,
        join_position,
    )
    .await?
    {
        return Ok(Some(genesis_floor.clone()));
    }
    held_join_floor(conn, realm_id, join_commit_id, join_position).await
}

async fn direct_founding_join_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    genesis_floor: &ReadableFloor,
    join_commit_id: &str,
    join_position: i64,
) -> PersistenceResult<bool> {
    // Both members of the registered four-Event Direct founding unit joined
    // atomically with genesis. Match the current membership's exact Commit,
    // rather than treating a later rejoin (or merely this Realm's purpose) as
    // founding history access.
    let direct_founding = sql_query(
        "SELECT EXISTS (SELECT 1 FROM direct_conversation_founding_slots f \
         WHERE f.realm_id=$1 AND jsonb_array_length(f.commits_json)=4 \
         AND f.commits_json->0->>'commit_id'=$3 \
         AND EXISTS (SELECT 1 FROM jsonb_array_elements(f.commits_json) \
             WITH ORDINALITY AS c(value,ordinality) \
             WHERE c.ordinality IN (2,3) AND c.value->>'commit_id'=$2 \
             AND (c.ordinality-1)=$4) \
         AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(f.commits_json) \
             WITH ORDINALITY AS c(value,ordinality) \
             WHERE c.value->>'realm_id' IS DISTINCT FROM $1 \
             OR c.value->'stream_ref' IS DISTINCT FROM $5 \
             OR c.value->>'stream_position' IS DISTINCT FROM (c.ordinality-1)::text \
             OR NOT EXISTS (SELECT 1 FROM realm_commits r \
                 WHERE r.commit_id=c.value->>'commit_id' AND r.realm_id=$1 \
                 AND r.stream_key=$6 AND r.stream_position=c.ordinality-1 \
                 AND r.previous_commit_ref IS NOT DISTINCT FROM \
                     CASE WHEN c.ordinality=1 THEN NULL \
                     ELSE f.commits_json->((c.ordinality-2)::int)->>'commit_id' END)) \
         ) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(join_commit_id)
    .bind::<Text, _>(genesis_floor.floor_commit_id.as_str())
    .bind::<BigInt, _>(join_position)
    .bind::<Jsonb, _>(
        serde_json::to_value(CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        })
        .map_err(PersistenceError::database)?,
    )
    .bind::<Text, _>(crate::authority_commit::stream_key(
        &CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
    )?)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(direct_founding.present)
}

/// Bootstrap narrows an ordinary opening join to its own position. An exact
/// registered atomic unit is the exception: its current opening join and
/// position zero were accepted together, so the canonical floor remains zero.
/// This is not the all-history policy shortcut used by ordinary scan reads.
pub(crate) async fn bootstrap_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    stream: &CommitStreamRef,
    join_commit_id: &str,
    join_position: i64,
) -> PersistenceResult<u64> {
    let position = u64::try_from(join_position)
        .map_err(|_| PersistenceError::Internal("stored join position is negative".into()))?;
    if registered_atomic_join_in_connection(conn, realm_id, stream, join_commit_id, join_position)
        .await?
    {
        return Ok(0);
    }
    Ok(position)
}

/// Prove that this exact current join belongs to a complete accepted founding
/// unit, including its held genesis and continuous physical Commit prefix.
/// A retained slot, Realm purpose, low position or former join is insufficient.
pub(crate) async fn registered_atomic_join_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    stream: &CommitStreamRef,
    join_commit_id: &str,
    join_position: i64,
) -> PersistenceResult<bool> {
    if !matches!(stream, CommitStreamRef::Realm { realm_id: held } if held == realm_id) {
        return Ok(false);
    }
    let Some(genesis) = held_genesis_floor_in_connection(conn, realm_id).await? else {
        return Ok(false);
    };
    let ordinary = sql_query(
        "SELECT EXISTS (SELECT 1 FROM ordinary_realm_bootstrap_units u \
         WHERE u.realm_id=$1 AND u.commits_json->0->>'commit_id'=$3 \
         AND EXISTS (SELECT 1 FROM jsonb_array_elements(u.commits_json) \
             WITH ORDINALITY AS c(value,ordinality) \
             WHERE c.value->>'commit_id'=$2 AND (c.ordinality-1)=$4) \
         AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(u.commits_json) \
             WITH ORDINALITY AS c(value,ordinality) \
             WHERE c.value->>'realm_id' IS DISTINCT FROM $1 \
             OR c.value->'stream_ref' IS DISTINCT FROM $5 \
             OR c.value->>'stream_position' IS DISTINCT FROM (c.ordinality-1)::text \
             OR NOT EXISTS (SELECT 1 FROM realm_commits r \
                 WHERE r.commit_id=c.value->>'commit_id' AND r.realm_id=$1 \
                 AND r.stream_key=$6 AND r.stream_position=c.ordinality-1 \
                 AND r.previous_commit_ref IS NOT DISTINCT FROM \
                     CASE WHEN c.ordinality=1 THEN NULL \
                     ELSE u.commits_json->((c.ordinality-2)::int)->>'commit_id' END)) \
         ) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(join_commit_id)
    .bind::<Text, _>(genesis.floor_commit_id.as_str())
    .bind::<BigInt, _>(join_position)
    .bind::<Jsonb, _>(serde_json::to_value(stream).map_err(PersistenceError::database)?)
    .bind::<Text, _>(crate::authority_commit::stream_key(stream)?)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(ordinary.present
        || direct_founding_join_in_connection(
            conn,
            realm_id,
            &genesis,
            join_commit_id,
            join_position,
        )
        .await?)
}

/// The `membership_join` floor at a join Commit this Station holds on the
/// Realm stream.
async fn held_join_floor(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    join_commit_id: &str,
    join_position: i64,
) -> PersistenceResult<Option<ReadableFloor>> {
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let on_stream = sql_query(
        "SELECT EXISTS (SELECT 1 FROM realm_commits \
         WHERE commit_id=$1 AND stream_key=$2 AND stream_position=$3) AS present",
    )
    .bind::<Text, _>(join_commit_id)
    .bind::<Text, _>(crate::authority_commit::stream_key(&realm_stream)?)
    .bind::<BigInt, _>(join_position)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !on_stream.present {
        return Ok(None);
    }
    Ok(Some(ReadableFloor {
        oldest_position: u64::try_from(join_position).map_err(|_| {
            PersistenceError::Internal("stored join position is negative".to_owned())
        })?,
        floor_commit_id: join_commit_id.parse().map_err(|error| {
            PersistenceError::Internal(format!("stored join Commit id is invalid: {error}"))
        })?,
        floor_reason: ReadableFloorReason::MembershipJoin,
    }))
}

async fn current_join(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &ActorId,
) -> PersistenceResult<Option<JoinRow>> {
    Ok(sql_query(
        "SELECT membership, current_commit_id, current_stream_position \
         FROM member_state_current_states WHERE realm_id=$1 AND member_id=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .get_result::<JoinRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .filter(|row| row.membership == "join"))
}

/// The caller's readable floor on the Realm stream at this governing read
/// cut, or `None` when it is not provable here. A member that left and
/// rejoined reads only from its current join.
pub(crate) async fn caller_realm_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    caller: &ActorId,
) -> PersistenceResult<Option<ReadableFloor>> {
    let controller = crate::agent_management_admission::read_controller_in_connection(
        conn, realm_id, None, caller,
    )
    .await?;
    let Some(mut floor) = member_realm_floor_in_connection(conn, realm_id, caller).await? else {
        return Ok(None);
    };
    if let Some(controller) = controller {
        let Some(controller_floor) =
            member_realm_floor_in_connection(conn, realm_id, &controller).await?
        else {
            return Ok(None);
        };
        if controller_floor.oldest_position > floor.oldest_position {
            floor = controller_floor;
        }
    }
    Ok(Some(floor))
}

async fn member_realm_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    caller: &ActorId,
) -> PersistenceResult<Option<ReadableFloor>> {
    let Some(genesis_floor) = genesis_floor_in_connection(conn, realm_id).await? else {
        return Ok(None);
    };
    let Some(join) = current_join(conn, realm_id, caller).await? else {
        return Ok(None);
    };
    join_floor_in_connection(
        conn,
        realm_id,
        &genesis_floor,
        &join.current_commit_id,
        join.current_stream_position,
    )
    .await
}

/// Snapshot disclosure uses the same proven interval as the Account scan.
/// A since-join replica need not hold the prefix preceding its opening join.
pub(crate) async fn snapshot_realm_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    caller: &ActorId,
) -> PersistenceResult<Option<ReadableFloor>> {
    let stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let genesis = sql_query(
        "SELECT EXISTS (SELECT 1 FROM realm_commits \
         WHERE stream_key=$1 AND stream_position=0) AS present",
    )
    .bind::<Text, _>(crate::authority_commit::stream_key(&stream)?)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if genesis.present {
        return caller_realm_floor_in_connection(conn, realm_id, caller).await;
    }
    match replica_realm_floor_in_connection(conn, realm_id, caller).await? {
        Ok(floor) => Ok(Some(floor)),
        Err(_) => Ok(None),
    }
}

#[derive(QueryableByName)]
struct ReplicaAnchorRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    anchor_commit_id: Option<String>,
    #[diesel(sql_type = BigInt)]
    join_position: i64,
}

async fn circle_history_access(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    circle_id: &arkret_wire::CircleId,
) -> PersistenceResult<Option<arkret_wire::HistoryAccess>> {
    let Some(row) =
        sql_query("SELECT value FROM circle_current_states WHERE realm_id=$1 AND circle_id=$2")
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(circle_id.as_str())
            .get_result::<ValueRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
    else {
        return Ok(None);
    };
    let circle: arkret_models_collaboration::governance::circle::Circle =
        serde_json::from_value(row.value).map_err(PersistenceError::database)?;
    if circle.id.as_ref() != Some(circle_id) || circle.realm_id != *realm_id {
        return Err(PersistenceError::SchemaViolation(
            "Circle history subject differs from its accepted current".to_owned(),
        ));
    }
    Ok(Some(circle.history_access))
}

async fn current_circle_join(
    conn: &mut AsyncPgConnection,
    stream: &CommitStreamRef,
    caller: &ActorId,
) -> PersistenceResult<Option<JoinRow>> {
    let CommitStreamRef::Circle {
        realm_id,
        circle_id,
    } = stream
    else {
        return Ok(None);
    };
    sql_query(
        "SELECT m.membership,m.current_commit_id,m.current_stream_position \
        FROM circle_member_state_current_states m \
        WHERE m.realm_id=$1 AND m.circle_id=$2 AND m.member_id=$3 AND m.membership='join' \
        AND m.value->>'membership'='join' AND m.source_stream_ref=$5 \
        AND circle_member_parent_join_current(m.realm_id,m.member_id,m.value) \
        AND (EXISTS (SELECT 1 FROM realm_commits c WHERE c.realm_id=m.realm_id \
             AND c.commit_id=m.current_commit_id AND c.stream_position=m.current_stream_position \
             AND c.stream_key=$4 AND c.stream_ref=m.source_stream_ref) \
          OR EXISTS (SELECT 1 FROM replica_stream_anchors a WHERE a.realm_id=m.realm_id \
             AND a.stream_key=$4 AND a.anchor_commit_id IS NOT NULL \
             AND a.anchor_stream_position>=m.current_stream_position))",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(circle_id.as_str())
    .bind::<Text, _>(caller.to_string())
    .bind::<Text, _>(crate::authority_commit::stream_key(stream)?)
    .bind::<Jsonb, _>(serde_json::to_value(stream).map_err(PersistenceError::database)?)
    .get_result::<JoinRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)
}

async fn circle_join_floor(
    conn: &mut AsyncPgConnection,
    stream: &CommitStreamRef,
    join: &JoinRow,
    history: arkret_wire::HistoryAccess,
) -> PersistenceResult<Option<ReadableFloor>> {
    let join_position = u64::try_from(join.current_stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("Circle join position is negative".to_owned())
    })?;
    // A since-join replica is not entitled to download the private prefix
    // before its opening join. The exact proven join is its readable floor;
    // requiring a locally held position zero would reject that valid interval.
    if history == arkret_wire::HistoryAccess::SinceJoin && join_position > 0 {
        return Ok(Some(ReadableFloor {
            oldest_position: join_position,
            floor_commit_id: join
                .current_commit_id
                .parse()
                .map_err(PersistenceError::database)?,
            floor_reason: ReadableFloorReason::MembershipJoin,
        }));
    }
    let Some(genesis) = crate::authority_commit::stream_page_in_connection(
        conn,
        &StreamScanRequestBody {
            realm_id: stream.realm_id().clone(),
            stream_ref: stream.clone(),
            direction: arkret_wire::StreamScanDirection::After(None),
            limit: 1,
        },
    )
    .await?
    .readable_floor
    else {
        return Ok(None);
    };
    match history {
        arkret_wire::HistoryAccess::AllHistoryForCurrentMembers => Ok(Some(genesis)),
        arkret_wire::HistoryAccess::SinceJoin => {
            let join_position = u64::try_from(join.current_stream_position).map_err(|_| {
                PersistenceError::SchemaViolation("Circle join position is negative".to_owned())
            })?;
            if genesis.oldest_position > join_position {
                return Ok(Some(genesis));
            }
            if join_position == 0 {
                if join.current_commit_id != genesis.floor_commit_id.as_str() {
                    return Err(PersistenceError::SchemaViolation(
                        "Circle opening join does not match its stream-start Commit".to_owned(),
                    ));
                }
                return Ok(Some(genesis));
            }
            Ok(Some(ReadableFloor {
                oldest_position: join_position,
                floor_commit_id: join
                    .current_commit_id
                    .parse()
                    .map_err(PersistenceError::database)?,
                floor_reason: ReadableFloorReason::MembershipJoin,
            }))
        }
    }
}

/// A Circle's interval requires current parent-Realm and exact Circle joins.
/// Each Circle position is independent of the parent's Realm position.
pub(crate) async fn caller_circle_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    circle_id: &arkret_wire::CircleId,
    caller: &ActorId,
) -> PersistenceResult<Option<ReadableFloor>> {
    let controller = crate::agent_management_admission::read_controller_in_connection(
        conn,
        realm_id,
        Some(circle_id),
        caller,
    )
    .await?;
    let Some(mut floor) =
        member_circle_floor_in_connection(conn, realm_id, circle_id, caller).await?
    else {
        return Ok(None);
    };
    if let Some(controller) = controller {
        let Some(controller_floor) =
            member_circle_floor_in_connection(conn, realm_id, circle_id, &controller).await?
        else {
            return Ok(None);
        };
        if controller_floor.oldest_position > floor.oldest_position {
            floor = controller_floor;
        }
    }
    Ok(Some(floor))
}

async fn member_circle_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    circle_id: &arkret_wire::CircleId,
    caller: &ActorId,
) -> PersistenceResult<Option<ReadableFloor>> {
    if !crate::authority_commit::accepted_current_member_joined_in_connection(
        conn, realm_id, caller,
    )
    .await?
    {
        return Ok(None);
    }
    let stream = CommitStreamRef::Circle {
        realm_id: realm_id.clone(),
        circle_id: circle_id.clone(),
    };
    let Some(join) = current_circle_join(conn, &stream, caller).await? else {
        return Ok(None);
    };
    crate::circle_current_states::require_member_current_in_connection(
        conn, realm_id, circle_id, caller,
    )
    .await?;
    let Some(history) = circle_history_access(conn, realm_id, circle_id).await? else {
        return Ok(None);
    };
    circle_join_floor(conn, &stream, &join, history).await
}

pub(crate) async fn replica_circle_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    circle_id: &arkret_wire::CircleId,
    caller: &ActorId,
) -> PersistenceResult<Result<ReadableFloor, &'static str>> {
    let stream = CommitStreamRef::Circle {
        realm_id: realm_id.clone(),
        circle_id: circle_id.clone(),
    };
    let Some(anchor) = sql_query(
        "SELECT a.anchor_commit_id,c.stream_position AS join_position \
        FROM replica_stream_anchors a JOIN realm_commits c ON c.commit_id=a.join_commit_id \
        WHERE a.realm_id=$1 AND a.stream_key=$2 AND c.stream_key=a.stream_key",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(crate::authority_commit::stream_key(&stream)?)
    .get_result::<ReplicaAnchorRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    else {
        return Ok(Err("the Circle stream is not held here"));
    };
    if anchor.anchor_commit_id.is_none() {
        return Ok(Err("the Circle stream is pending its bootstrap anchor"));
    }
    let history = circle_history_access(conn, realm_id, circle_id).await?;
    let Some(join) = current_circle_join(conn, &stream, caller).await? else {
        return Ok(Err("the caller has no held Circle join"));
    };
    crate::circle_current_states::require_member_current_in_connection(
        conn, realm_id, circle_id, caller,
    )
    .await?;
    if history == Some(arkret_wire::HistoryAccess::SinceJoin)
        && join.current_stream_position < anchor.join_position
    {
        return Ok(Err("the caller's Circle join precedes the held stream"));
    }
    let Some(floor) = caller_circle_floor_in_connection(conn, realm_id, circle_id, caller).await?
    else {
        return Ok(Err("the held Circle membership scope is unproved"));
    };
    if history == Some(arkret_wire::HistoryAccess::AllHistoryForCurrentMembers)
        && floor.oldest_position != 0
    {
        return Ok(Err("the Circle's complete history is not held here"));
    }
    Ok(Ok(floor))
}

/// The caller's readable floor on a Realm stream this member Station holds
/// as an anchored replica: under `since_join` its own held join Commit, at
/// or after the join that opened the held stream. An atomic founding replica
/// also holds position zero, so its founding members use the same unit floor
/// as the governing Station. An absent earlier prefix remains unproved.
pub(crate) async fn replica_realm_floor_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    caller: &ActorId,
) -> PersistenceResult<Result<ReadableFloor, &'static str>> {
    let Some(anchor) = sql_query(
        "SELECT a.anchor_commit_id, c.stream_position AS join_position \
         FROM replica_stream_anchors a JOIN realm_commits c ON c.commit_id=a.join_commit_id \
         WHERE a.realm_id=$1 AND a.stream_key=$2 AND c.stream_key=a.stream_key",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(crate::authority_commit::stream_key(
        &CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
    )?)
    .get_result::<ReplicaAnchorRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    else {
        return Ok(Err(
            "this Station neither governs nor holds the Realm stream",
        ));
    };
    if anchor.anchor_commit_id.is_none() {
        return Ok(Err("the held Realm stream is pending its bootstrap anchor"));
    }
    if realm_history_access(conn, realm_id).await?.as_deref() != Some("since_join") {
        return Ok(Err(
            "the history before this Station's held join is not held here",
        ));
    }
    let Some(join) = current_join(conn, realm_id, caller).await? else {
        return Ok(Err("the caller has no held join"));
    };
    if join.current_stream_position < anchor.join_position {
        return Ok(Err(
            "the caller's join precedes the Realm stream this Station holds",
        ));
    }
    if let Some(genesis_floor) = held_genesis_floor_in_connection(conn, realm_id).await? {
        return Ok(join_floor_in_connection(
            conn,
            realm_id,
            &genesis_floor,
            &join.current_commit_id,
            join.current_stream_position,
        )
        .await?
        .ok_or("the caller's held unit floor is not proved"));
    }
    Ok(held_join_floor(
        conn,
        realm_id,
        &join.current_commit_id,
        join.current_stream_position,
    )
    .await?
    .ok_or("the caller's join Commit is not held"))
}

#[derive(QueryableByName)]
struct PriorJoinRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    membership: Option<String>,
}

#[derive(QueryableByName)]
struct HostedMemberRow {
    #[diesel(sql_type = Text)]
    member_id: String,
    #[diesel(sql_type = Text)]
    membership: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

/// One interval of a peer Station's replication right on the Realm stream:
/// from `floor` through `last` (to the head when `None`).
struct PeerInterval {
    floor: ReadableFloor,
    last: Option<u64>,
}

impl PeerInterval {
    fn covers(&self, position: u64) -> bool {
        position >= self.floor.oldest_position && self.last.is_none_or(|last| position <= last)
    }
}

/// The membership Event that preceded `terminal_position` for `member`, when
/// it was a join (`ak.member.state{join}` or the member's `ak.invite.accept`).
async fn prior_join(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &str,
    terminal_position: i64,
) -> PersistenceResult<Option<PriorJoinRow>> {
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    Ok(sql_query(
        "SELECT c.commit_id, c.stream_position, e.kind, \
                e.envelope->'payload'->>'membership' AS membership \
         FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.stream_key=$1 AND c.stream_position < $2 AND e.state='committed' AND ( \
           (e.kind='ak.member.state' AND e.envelope->'payload'->'member_id'=$3::jsonb) \
           OR (e.kind IN ('ak.invite.accept','ak.realm_invite_link.accept') AND e.envelope->'actor_id'=$3::jsonb)) \
         ORDER BY c.stream_position DESC LIMIT 1",
    )
    .bind::<Text, _>(crate::authority_commit::stream_key(&realm_stream)?)
    .bind::<BigInt, _>(terminal_position)
    .bind::<Text, _>(member)
    .get_result::<PriorJoinRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .filter(|row| {
        matches!(arkret_wire::EventKind::from_wire(&row.kind), arkret_wire::EventKind::InviteAccept | arkret_wire::EventKind::RealmInviteLinkAccept)
            || row.membership.as_deref() == Some("join")
    }))
}

/// Prove a peer interval from a full governing prefix or a verified held
/// since-join suffix. A replica need not possess position zero; its durable
/// bootstrap anchor and exact held join bound its retained interval instead.
async fn peer_realm_join_floor(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    genesis_floor: Option<&ReadableFloor>,
    join_commit_id: &str,
    join_position: i64,
) -> PersistenceResult<Option<ReadableFloor>> {
    if let Some(genesis_floor) = genesis_floor {
        return join_floor_in_connection(
            conn,
            realm_id,
            genesis_floor,
            join_commit_id,
            join_position,
        )
        .await;
    }
    if realm_history_access(conn, realm_id).await?.as_deref() != Some("since_join") {
        return Ok(None);
    }
    let anchor = sql_query(
        "SELECT a.anchor_commit_id,c.stream_position AS join_position \
         FROM replica_stream_anchors a JOIN realm_commits c ON c.commit_id=a.join_commit_id \
         WHERE a.realm_id=$1 AND a.stream_key=$2 AND c.stream_key=a.stream_key",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(crate::authority_commit::stream_key(
        &CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
    )?)
    .get_result::<ReplicaAnchorRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if anchor.is_none_or(|anchor| {
        anchor.anchor_commit_id.is_none() || join_position < anchor.join_position
    }) {
        return Ok(None);
    }
    held_join_floor(conn, realm_id, join_commit_id, join_position).await
}

/// Every interval of `peer`'s replication right on the Realm stream at this
/// governing cut, with the members routed to it.
async fn peer_intervals(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    peer: &DidCoreId,
) -> PersistenceResult<(Vec<PeerInterval>, Vec<ActorId>)> {
    let rows = sql_query(
        "SELECT member_id, membership, current_commit_id, current_stream_position \
         FROM member_state_current_states WHERE realm_id=$1 ORDER BY member_id",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<HostedMemberRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut hosted = Vec::new();
    for row in rows {
        let member: ActorId = serde_json::from_str(&row.member_id).map_err(|error| {
            PersistenceError::Internal(format!("stored member ActorId is invalid: {error}"))
        })?;
        if member.fixed_route_service_id() == Some(peer) {
            hosted.push((member, row));
        }
    }
    let mut intervals = Vec::new();
    let mut joined = Vec::new();
    if hosted.is_empty() {
        return Ok((intervals, joined));
    }
    let genesis_floor = held_genesis_floor_in_connection(conn, realm_id).await?;
    for (member, row) in hosted {
        match row.membership.as_str() {
            "join" => {
                if let Some(floor) = peer_realm_join_floor(
                    conn,
                    realm_id,
                    genesis_floor.as_ref(),
                    &row.current_commit_id,
                    row.current_stream_position,
                )
                .await?
                {
                    intervals.push(PeerInterval { floor, last: None });
                }
                joined.push(member);
            }
            // A leave or ban that ended the member's joined state keeps the
            // right through that terminating Commit (`federation.md` §4.1.1).
            "leave" | "ban" => {
                let Some(join) =
                    prior_join(conn, realm_id, &row.member_id, row.current_stream_position).await?
                else {
                    continue;
                };
                if let Some(floor) = peer_realm_join_floor(
                    conn,
                    realm_id,
                    genesis_floor.as_ref(),
                    &join.commit_id,
                    join.stream_position,
                )
                .await?
                {
                    intervals.push(PeerInterval {
                        floor,
                        last: Some(u64::try_from(row.current_stream_position).map_err(|_| {
                            PersistenceError::Internal(
                                "stored membership position is negative".to_owned(),
                            )
                        })?),
                    });
                }
            }
            _ => {}
        }
    }
    Ok((intervals, joined))
}

/// A Circle replication interval uses only coordinates on that Circle.
/// A parent membership is a prerequisite, never a child-stream cursor.
async fn peer_circle_intervals(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    circle_id: &arkret_wire::CircleId,
    peer: &DidCoreId,
) -> PersistenceResult<(Vec<PeerInterval>, Vec<ActorId>)> {
    let stream = CommitStreamRef::Circle {
        realm_id: realm_id.clone(),
        circle_id: circle_id.clone(),
    };
    let key = crate::authority_commit::stream_key(&stream)?;
    let Some(history) = circle_history_access(conn, realm_id, circle_id).await? else {
        return Ok((Vec::new(), Vec::new()));
    };
    let rows = sql_query(
        "SELECT m.member_id,m.membership,m.current_commit_id,m.current_stream_position \
         FROM circle_member_state_current_states m JOIN realm_commits c \
           ON c.commit_id=m.current_commit_id AND c.realm_id=m.realm_id \
           AND c.stream_position=m.current_stream_position AND c.stream_ref=m.source_stream_ref \
         WHERE m.realm_id=$1 AND m.circle_id=$2 AND c.stream_key=$3 \
           AND m.value->>'membership'=m.membership \
           AND (m.membership<>'join' \
             OR circle_member_parent_join_current(m.realm_id,m.member_id,m.value)) \
         ORDER BY m.member_id",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(circle_id.as_str())
    .bind::<Text, _>(&key)
    .load::<HostedMemberRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut intervals = Vec::new();
    let mut joined = Vec::new();
    for row in rows {
        let member: ActorId =
            serde_json::from_str(&row.member_id).map_err(PersistenceError::database)?;
        if member.fixed_route_service_id() != Some(peer)
            || !crate::authority_commit::accepted_current_member_joined_in_connection(
                conn, realm_id, &member,
            )
            .await?
        {
            continue;
        }
        let (join, last) = match row.membership.as_str() {
            "join" => (
                JoinRow {
                    membership: row.membership.clone(),
                    current_commit_id: row.current_commit_id.clone(),
                    current_stream_position: row.current_stream_position,
                },
                None,
            ),
            "leave" | "ban" => {
                let Some(prior) = sql_query(
                    "SELECT c.commit_id,c.stream_position,e.kind,e.envelope->'payload'->>'membership' AS membership \
                     FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
                     WHERE c.stream_key=$1 AND c.stream_position<$2 AND e.state='committed' \
                       AND e.kind='ak.circle.member.state' AND e.envelope->'payload'->'member_id'=$3::jsonb \
                     ORDER BY c.stream_position DESC LIMIT 1",
                ).bind::<Text,_>(&key).bind::<BigInt,_>(row.current_stream_position).bind::<Text,_>(&row.member_id)
                    .get_result::<PriorJoinRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
                else { continue; };
                if prior.membership.as_deref() != Some("join") {
                    continue;
                }
                (
                    JoinRow {
                        membership: "join".to_owned(),
                        current_commit_id: prior.commit_id,
                        current_stream_position: prior.stream_position,
                    },
                    Some(u64::try_from(row.current_stream_position).map_err(|_| {
                        PersistenceError::SchemaViolation(
                            "Circle terminal position is negative".to_owned(),
                        )
                    })?),
                )
            }
            _ => continue,
        };
        if let Some(floor) = circle_join_floor(conn, &stream, &join, history).await? {
            intervals.push(PeerInterval { floor, last });
            if last.is_none() {
                joined.push(member);
            }
        }
    }
    Ok((intervals, joined))
}

async fn peer_stream_intervals(
    conn: &mut AsyncPgConnection,
    stream: &CommitStreamRef,
    peer: &DidCoreId,
) -> PersistenceResult<(Vec<PeerInterval>, Vec<ActorId>)> {
    match stream {
        CommitStreamRef::RealmControl { .. } => Ok((Vec::new(), Vec::new())),
        CommitStreamRef::Realm { realm_id } => peer_intervals(conn, realm_id, peer).await,
        CommitStreamRef::Circle {
            realm_id,
            circle_id,
        } => peer_circle_intervals(conn, realm_id, circle_id, peer).await,
        CommitStreamRef::Sidecar {
            realm_id,
            sidecar_id,
        } => {
            #[derive(QueryableByName)]
            struct Owner {
                #[diesel(sql_type = Jsonb)]
                controller_account_id: serde_json::Value,
            }
            let owner = sql_query("SELECT controller_account_id FROM sidecar_current_states WHERE realm_id=$1 AND sidecar_id=$2")
                .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(sidecar_id.as_str())
                .get_result::<Owner>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            let Some(owner) = owner else {
                return Ok((Vec::new(), Vec::new()));
            };
            let account: AccountId = serde_json::from_value(owner.controller_account_id)
                .map_err(PersistenceError::database)?;
            if &account.station_id != peer {
                return Ok((Vec::new(), Vec::new()));
            }
            let actor = ActorId::account(account);
            let Some(floor) = crate::sidecar_authority_cut::controller_floor_in_connection(
                conn, realm_id, sidecar_id, &actor,
            )
            .await?
            else {
                return Ok((Vec::new(), Vec::new()));
            };
            Ok((vec![PeerInterval { floor, last: None }], vec![actor]))
        }
        _ => Ok((Vec::new(), Vec::new())),
    }
}

/// The authenticated source Station's replication interval at one already
/// selected accepted Commit, inside the caller's governing RR read cut.
pub(crate) async fn peer_replication_right_at_in_connection(
    conn: &mut AsyncPgConnection,
    stream: &CommitStreamRef,
    peer: &DidCoreId,
    position: u64,
) -> PersistenceResult<bool> {
    let (intervals, _) = peer_stream_intervals(conn, stream, peer).await?;
    Ok(intervals.iter().any(|interval| interval.covers(position)))
}

/// Whether `peer` may hold the complete canonical bytes of `event` at this
/// cut: the same content rule the fanout target set applies.
async fn peer_holds_full_event(
    conn: &mut AsyncPgConnection,
    row: &arkret_wire::CommittedEventFullView,
    peer: &DidCoreId,
    joined: &[ActorId],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<bool> {
    let event = &row.event;
    if crate::realm_fanout::plaintext_message(event) {
        let services = sql_query(
            "SELECT value FROM realm_bootstrap_current_states \
             WHERE realm_id=$1 AND state_family='realm_plaintext_visible_services'",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .get_result::<ValueRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(|row| crate::realm_fanout::plaintext_message_service_ids(&row.value))
        .unwrap_or_default();
        if !services.iter().any(|service| service == peer.as_str()) {
            return Ok(false);
        }
    }
    // The interval already proves this peer's right through a leave/ban.
    // Its terminating membership fact must remain consumable after the
    // member ceases to be current; no content right follows from it.
    if matches!(
        event.kind,
        arkret_wire::EventKind::MemberState | arkret_wire::EventKind::CircleMemberState
    ) && matches!(
        event
            .payload
            .get("membership")
            .and_then(serde_json::Value::as_str),
        Some("leave" | "ban")
    ) && let Some(target) = event.payload.get("member_id")
    {
        let member: ActorId =
            serde_json::from_value(target.clone()).map_err(PersistenceError::database)?;
        if member.fixed_route_service_id() == Some(peer) {
            return Ok(true);
        }
    }
    if matches!(event.scope_ref, arkret_wire::ScopeRef::Realm { .. })
        && !matches!(
            event.kind,
            arkret_wire::EventKind::CircleCreate
                | arkret_wire::EventKind::SelfModerationReport
                | arkret_wire::EventKind::ModerationFrankingProof
        )
        && crate::snapshot_disclosure_gate::member_shared_event_kind(&event.kind)
    {
        return Ok(true);
    }
    for member in joined {
        if crate::committed_disclosure::full_event_for_member_in_connection(conn, row, member, at)
            .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(QueryableByName)]
struct CommittedRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
}

/// The committed Event `event_id` when `peer` may read it at this governing
/// cut: its Realm-stream Commit lies in one of the peer's replication
/// intervals and the peer may hold its complete canonical bytes.
pub(crate) async fn committed_event_for_peer(
    pool: &PgPool,
    event_id: &arkret_wire::EventId,
    peer: &DidCoreId,
    issuer: &DidCoreId,
) -> PersistenceResult<Option<arkret_wire::CommittedEventFullView>> {
    let token = crate::ids::parse_event_id(event_id.as_str())
        .ok_or_else(|| PersistenceError::SchemaViolation("Event id is not canonical".to_owned()))?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        let Some(row) = sql_query(
            "SELECT c.commit_json, e.envelope FROM canonical_events e \
             JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.state='committed'",
        )
        .bind::<diesel::sql_types::Binary, _>(token.to_vec())
        .get_result::<CommittedRow>(&mut *conn)
        .await
        .optional()?
        else {
            return Ok(None);
        };
        let invalid = |what: &str, error: serde_json::Error| {
            PgTransactionError::from(PersistenceError::Internal(format!(
                "stored committed {what} is invalid: {error}"
            )))
        };
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(row.commit_json).map_err(|error| invalid("Commit", error))?;
        let event: arkret_wire::Event =
            serde_json::from_value(row.envelope).map_err(|error| invalid("Event", error))?;
        let governs = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(event.realm_id.as_str())
            .get_result::<TenureRow>(&mut *conn)
            .await
            .optional()?
            .is_some_and(|tenure| tenure.service_id == issuer.as_str());
        if !governs || commit.stream_ref.realm_id() != &event.realm_id {
            return Ok(None);
        }
        let (intervals, joined) = peer_stream_intervals(conn, &commit.stream_ref, peer).await?;
        let full = arkret_wire::CommittedEventFullView { commit, event };
        if !intervals
            .iter()
            .any(|interval| interval.covers(full.commit.stream_position))
            || !peer_holds_full_event(conn, &full, peer, &joined, chrono::Utc::now()).await?
        {
            return Ok(None);
        }
        Ok(Some(full))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

#[derive(QueryableByName)]
struct ChainNodeRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
}

#[derive(QueryableByName)]
struct AnchorStateRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    anchor_commit_id: Option<String>,
}

/// The single disclosed row of a one-row disclosure.
fn single_row(mut rows: Vec<CommittedEventView>) -> PersistenceResult<CommittedEventView> {
    match (rows.pop(), rows.is_empty()) {
        (Some(row), true) => Ok(row),
        _ => Err(PersistenceError::Internal(
            "disclosure of one committed row returned another count".to_owned(),
        )),
    }
}

/// `ak.self.committed_event.resource.get.v1` for `caller` on an ordinary
/// Realm's Realm stream at one read cut of this Station, governing or holding
/// the stream as an anchored replica. The readable floor is the one the self
/// scan proves (`history-visibility.md` §3.1); on a member Station the
/// caller's current join row -- a held Commit or a row the anchored snapshot
/// covers -- gives it under `since_join`, and every held position is inside
/// it under `all_history_for_current_members`.
pub(crate) async fn committed_event_for_member(
    pool: &PgPool,
    event_id: &arkret_wire::EventId,
    caller: &ActorId,
    issuer: &DidCoreId,
) -> PersistenceResult<coland_storage::MemberCommittedEventRead> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        committed_event_for_member_in_connection(conn, event_id, caller, issuer).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn committed_event_for_member_in_connection(
    conn: &mut AsyncPgConnection,
    event_id: &arkret_wire::EventId,
    caller: &ActorId,
    issuer: &DidCoreId,
) -> Result<coland_storage::MemberCommittedEventRead, PgTransactionError> {
    use coland_storage::MemberCommittedEventRead as Read;
    let Some(token) = crate::ids::parse_event_id(event_id.as_str()) else {
        return Ok(Read::NotVisible);
    };
    let invalid = |what: &str, error: serde_json::Error| {
        PgTransactionError::from(PersistenceError::Internal(format!(
            "stored committed {what} is invalid: {error}"
        )))
    };
    let (commit, event) = if let Some(row) = sql_query(
        "SELECT c.commit_json, e.envelope FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.state='committed'",
    )
    .bind::<diesel::sql_types::Binary, _>(token.to_vec())
    .get_result::<CommittedRow>(&mut *conn)
    .await
    .optional()?
    {
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(row.commit_json).map_err(|error| invalid("Commit", error))?;
        let event: arkret_wire::Event =
            serde_json::from_value(row.envelope).map_err(|error| invalid("Event", error))?;
        (commit, Some(event))
    } else if let Some(row) = sql_query(
        "SELECT commit_json FROM realm_commits \
         WHERE event_pk IS NULL AND commit_json->>'event_ref'=$1",
    )
    .bind::<Text, _>(event_id.as_str())
    .get_result::<ChainNodeRow>(&mut *conn)
    .await
    .optional()?
    {
        let commit: arkret_wire::RealmCommit = serde_json::from_value(row.commit_json)
            .map_err(|error| invalid("chain node Commit", error))?;
        (commit, None)
    } else {
        return Ok(Read::NotVisible);
    };
    if matches!(commit.stream_ref, CommitStreamRef::RealmControl { .. }) {
        return Ok(Read::NotVisible);
    }
    let realm_id = commit.realm_id.clone();
    let anchor = sql_query(
        "SELECT anchor_commit_id FROM replica_stream_anchors WHERE realm_id=$1 AND stream_key=$2",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(crate::authority_commit::stream_key(&commit.stream_ref)?)
    .get_result::<AnchorStateRow>(&mut *conn)
    .await
    .optional()?;
    if anchor
        .as_ref()
        .is_some_and(|row| row.anchor_commit_id.is_none())
    {
        return Ok(Read::PendingAnchor);
    }
    if let CommitStreamRef::Circle { circle_id, .. } = &commit.stream_ref {
        let Some(tenure) = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result::<TenureRow>(&mut *conn)
            .await
            .optional()?
        else {
            return Ok(Read::NotVisible);
        };
        let floor = if tenure.service_id == issuer.as_str() {
            caller_circle_floor_in_connection(conn, &realm_id, circle_id, caller).await?
        } else {
            replica_circle_floor_in_connection(conn, &realm_id, circle_id, caller)
                .await?
                .ok()
        };
        if floor.is_none_or(|floor| commit.stream_position < floor.oldest_position) {
            return Ok(Read::NotVisible);
        }
        return Ok(Read::Read(Box::new(match event {
            Some(event) => single_row(
                crate::committed_disclosure::disclose_to_member_in_connection(
                    conn,
                    vec![arkret_wire::CommittedEventFullView { commit, event }],
                    caller,
                )
                .await?,
            )?,
            None => CommittedEventView::Withheld(arkret_wire::CommittedEventWithheldView {
                commit,
                event_disclosure: arkret_wire::EventDisclosure {
                    status: arkret_wire::EventDisclosureStatus::Withheld,
                },
            }),
        })));
    }
    if let CommitStreamRef::Sidecar { sidecar_id, .. } = &commit.stream_ref {
        let Some(tenure) = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(realm_id.as_str())
            .get_result::<TenureRow>(&mut *conn)
            .await
            .optional()?
        else {
            return Ok(Read::NotVisible);
        };
        let floor = if tenure.service_id == issuer.as_str() {
            crate::sidecar_authority_cut::public_material_floor_in_connection(
                conn, &realm_id, sidecar_id, caller,
            )
            .await?
        } else {
            crate::sidecar_replica_authority::handshake_floor_in_connection(
                conn, &realm_id, sidecar_id, caller,
            )
            .await?
            .unwrap_or_default()
        };
        if floor.is_none_or(|floor| commit.stream_position < floor.oldest_position) {
            return Ok(Read::NotVisible);
        }
        return Ok(Read::Read(Box::new(match event {
            Some(event) => single_row(
                crate::committed_disclosure::disclose_to_member_in_connection(
                    conn,
                    vec![arkret_wire::CommittedEventFullView { commit, event }],
                    caller,
                )
                .await?,
            )?,
            None => CommittedEventView::Withheld(arkret_wire::CommittedEventWithheldView {
                commit,
                event_disclosure: arkret_wire::EventDisclosure {
                    status: arkret_wire::EventDisclosureStatus::Withheld,
                },
            }),
        })));
    }
    if commit.stream_ref
        != (CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        })
    {
        return Ok(Read::OutsideOrdinaryRealmStream);
    }
    use arkret_models_collaboration::events_payloads::realm::RealmPurpose;
    // A control Realm's since_join history profile does not give it
    // ordinary membership. Its read path applies principal/controller gates.
    if matches!(
        realm_purpose(conn, &realm_id).await?,
        Some(RealmPurpose::PrincipalControl | RealmPurpose::AgentControl)
    ) {
        return Ok(Read::OutsideOrdinaryRealmStream);
    }
    let Some(history) = realm_history_access(conn, &realm_id).await? else {
        return Ok(Read::OutsideOrdinaryRealmStream);
    };
    if let Some(event) = &event
        && &event.actor_id == caller
        && event.kind != arkret_wire::EventKind::CircleCreate
    {
        let full = arkret_wire::CommittedEventFullView {
            commit,
            event: event.clone(),
        };
        return Ok(Read::Read(Box::new(single_row(
            crate::committed_disclosure::disclose_to_member_in_connection(conn, vec![full], caller)
                .await?,
        )?)));
    }
    let Some(tenure) = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<TenureRow>(&mut *conn)
        .await
        .optional()?
    else {
        return Ok(Read::NotVisible);
    };
    let governs = tenure.service_id == issuer.as_str();
    if (!governs && anchor.is_none())
        || !crate::authority_commit::accepted_current_member_joined_in_connection(
            conn, &realm_id, caller,
        )
        .await?
    {
        return Ok(Read::NotVisible);
    }
    // The genesis is a member of the Realm's authority bundle: every
    // current member resolves it.
    let genesis = commit.stream_position == 0
        && event
            .as_ref()
            .is_some_and(|event| event.kind == arkret_wire::EventKind::RealmCreate);
    if !genesis {
        let floor = if governs {
            match caller_realm_floor_in_connection(conn, &realm_id, caller).await? {
                Some(floor) => floor.oldest_position,
                None => return Ok(Read::NotVisible),
            }
        } else {
            match history.as_str() {
                "all_history_for_current_members" => 0,
                "since_join" => {
                    match replica_realm_floor_in_connection(conn, &realm_id, caller).await? {
                        Ok(floor) => floor.oldest_position,
                        Err(_) => return Ok(Read::NotVisible),
                    }
                }
                _ => return Ok(Read::NotVisible),
            }
        };
        if commit.stream_position < floor {
            return Ok(Read::NotVisible);
        }
    }
    let Some(event) = event else {
        return Ok(Read::Read(Box::new(CommittedEventView::Withheld(
            arkret_wire::CommittedEventWithheldView {
                commit,
                event_disclosure: arkret_wire::EventDisclosure {
                    status: arkret_wire::EventDisclosureStatus::Withheld,
                },
            },
        ))));
    };
    Ok(Read::Read(Box::new(single_row(
        crate::committed_disclosure::disclose_to_member_in_connection(
            conn,
            vec![arkret_wire::CommittedEventFullView { commit, event }],
            caller,
        )
        .await?,
    )?)))
}

pub(crate) async fn scan_stream_for_peer(
    pool: &PgPool,
    request: &StreamScanRequestBody,
    peer: &DidCoreId,
    issuer: &DidCoreId,
) -> PersistenceResult<coland_storage::PeerStreamScan> {
    request
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        let Some(tenure) = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(request.realm_id.as_str())
            .get_result::<TenureRow>(&mut *conn)
            .await
            .optional()?
        else {
            return Ok(coland_storage::PeerStreamScan::NotAuthorized);
        };
        if tenure.service_id != issuer.as_str() {
            return Ok(coland_storage::PeerStreamScan::Unproved(
                "this Station does not hold the Realm's governing tenure",
            ));
        }
        let (intervals, joined) = peer_stream_intervals(conn, &request.stream_ref, peer).await?;
        let Some(lowest) = intervals
            .iter()
            .min_by_key(|interval| interval.floor.oldest_position)
        else {
            return Ok(coland_storage::PeerStreamScan::NotAuthorized);
        };
        let floor = lowest.floor.clone();
        let last = if intervals.iter().any(|interval| interval.last.is_none()) {
            None
        } else {
            intervals.iter().filter_map(|interval| interval.last).max()
        };
        // A right that ends at a terminating Commit reads nothing after it.
        let mut bounded = request.clone();
        if let (Some(last), arkret_wire::StreamScanDirection::Before(before)) =
            (last, request.direction)
        {
            let cap = last.saturating_add(1);
            bounded.direction =
                arkret_wire::StreamScanDirection::Before(Some(before.map_or(cap, |p| p.min(cap))));
        }
        let mut page = crate::authority_commit::stream_page_above_floor_in_connection(
            conn,
            &bounded,
            Some(floor),
        )
        .await?;
        // Ascending scans end at the terminal Commit. A bounded reverse scan
        // can still have authorized older rows beyond this page's limit.
        if let Some(last) = last
            && matches!(request.direction, arkret_wire::StreamScanDirection::After(_))
            && page
                .committed_events
                .iter()
                .any(|item| item.commit().stream_position >= last)
        {
            page.committed_events
                .retain(|item| item.commit().stream_position <= last);
            page.truncated = false;
        }
        // A position outside every interval is not this peer's to read, not
        // even as a Commit: the page stops before it.
        if let Some(cut) = page.committed_events.iter().position(|item| {
            !intervals
                .iter()
                .any(|interval| interval.covers(item.commit().stream_position))
        }) {
            page.committed_events.truncate(cut);
            page.truncated = false;
        }
        let at = chrono::Utc::now();
        let mut full = Vec::new();
        let mut withheld = std::collections::BTreeSet::new();
        for item in &page.committed_events {
            let CommittedEventView::Full(view) = item else {
                return Err(PgTransactionError::from(PersistenceError::Internal(
                    "a governing stream page holds only full rows".to_owned(),
                )));
            };
            if !peer_holds_full_event(conn, view, peer, &joined, at).await? {
                withheld.insert(view.commit.commit_id.clone());
            }
            full.push(view.clone());
        }
        let committed_events = crate::committed_disclosure::disclose_in_connection(conn, full)
            .await?
            .into_iter()
            .map(|item| match item {
                CommittedEventView::Full(view) if withheld.contains(&view.commit.commit_id) => {
                    CommittedEventView::Withheld(arkret_wire::CommittedEventWithheldView {
                        commit: view.commit,
                        event_disclosure: arkret_wire::EventDisclosure {
                            status: arkret_wire::EventDisclosureStatus::Withheld,
                        },
                    })
                }
                other => other,
            })
            .collect::<Vec<_>>();
        let mut producer_signer_facts = Vec::new();
        for row in &committed_events {
            if let CommittedEventView::Full(full) = row
                && let Some(fact) = crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(conn, &full.event, &full.commit).await? {
                    producer_signer_facts.push(arkret_models_collaboration::authority_commit::HistoricalProducerSignerFactEntry {
                        target: arkret_wire::CommittedEventRef { event_id: full.event.event_id.clone(), commit_id: full.commit.commit_id.clone(), stream_ref: full.commit.stream_ref.clone(), stream_position: full.commit.stream_position },
                        producer_signer_fact: fact,
                    });
                }
        }
        let outcome = arkret_models_collaboration::authority_commit::PeerStreamScanResponseBody {
            committed_events, readable_floor: page.readable_floor, truncated: page.truncated, producer_signer_facts,
        };
        outcome.validate_for_request(request).map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        Ok(coland_storage::PeerStreamScan::Page(outcome))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
