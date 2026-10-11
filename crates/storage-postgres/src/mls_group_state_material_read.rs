//! Member MLS public-material authorization at one PostgreSQL read cut.
//!
//! Circle reads require the same parent Realm join generation at the current
//! and historical Circle cuts. Positions are compared within one stream only.

use arkret_models_collaboration::events_payloads::MlsGenesisPayload;
use arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialRequestBody;
use arkret_wire::{
    ActorId, CommitStreamRef, CommittedEventFullView, CommittedEventView, DidCoreId, EventId,
    EventKind, MlsGroupCurrent, MlsGroupId, RealmId, ScopeRef,
};
use coland_storage::MlsMemberGroupStateMaterialRead as Read;
use diesel::sql_types::{Binary, Jsonb, Nullable};

use crate::{
    AsyncConnection, AsyncPgConnection, BigInt, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, pg_conn,
    sql_query,
};

#[derive(QueryableByName)]
struct CommitRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    envelope: Option<serde_json::Value>,
}

#[derive(QueryableByName)]
struct MemberRow {
    #[diesel(sql_type = Text)]
    membership: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
}

#[derive(QueryableByName)]
struct TenureRow {
    #[diesel(sql_type = Text)]
    service_id: String,
}

#[derive(QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    present: bool,
}

#[derive(QueryableByName)]
struct GroupRow {
    #[diesel(sql_type = Text)]
    mls_group_id: String,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

/// The selectors common to public material and signed historical roster
/// reads. In particular it has no Genesis Blob refs: a newly joined member
/// must be able to authorize the roster before learning those refs.
pub(crate) struct MemberMlsTargetSelector {
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub mls_group_id: MlsGroupId,
    pub group_state_event_id: Option<EventId>,
    pub caller_actor_id: ActorId,
    pub target_commit_event_ref: EventId,
    pub target_epoch: u64,
}

async fn accepted_row(
    conn: &mut AsyncPgConnection,
    event_ref: &arkret_wire::EventId,
) -> PersistenceResult<Option<CommitRow>> {
    let Some(token) = crate::ids::parse_event_id(event_ref.as_str()) else {
        return Ok(None);
    };
    let full = sql_query(
        "SELECT c.commit_json,e.envelope FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.state='committed'",
    )
    .bind::<Binary, _>(token.to_vec())
    .get_result::<CommitRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if full.is_some() {
        return Ok(full);
    }
    sql_query(
        "SELECT commit_json,NULL::jsonb AS envelope FROM realm_commits \
         WHERE event_pk IS NULL AND commit_json->>'event_ref'=$1",
    )
    .bind::<Text, _>(event_ref.as_str())
    .get_result::<CommitRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)
}

fn decode_commit(row: &CommitRow) -> PersistenceResult<arkret_wire::RealmCommit> {
    serde_json::from_value(row.commit_json.clone()).map_err(|error| {
        PersistenceError::Internal(format!("stored MLS material Commit is invalid: {error}"))
    })
}

fn decode_event(row: &CommitRow) -> PersistenceResult<Option<arkret_wire::Event>> {
    row.envelope
        .as_ref()
        .map(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                PersistenceError::Internal(format!("stored MLS material Event is invalid: {error}"))
            })
        })
        .transpose()
}

async fn founding_join(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    join_commit_id: &str,
) -> PersistenceResult<bool> {
    Ok(sql_query(
        "SELECT EXISTS (SELECT 1 FROM ordinary_realm_bootstrap_units u \
         CROSS JOIN LATERAL jsonb_array_elements(u.commits_json) c \
         WHERE u.realm_id=$1 AND c->>'commit_id'=$2) AS present",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(join_commit_id)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present)
}

pub(crate) async fn read_in_connection(
    conn: &mut AsyncPgConnection,
    request: &MemberMlsTargetSelector,
    issuer: &DidCoreId,
    source_peer: Option<&DidCoreId>,
) -> PersistenceResult<Read> {
    let caller = &request.caller_actor_id;
    let target_ref = &request.target_commit_event_ref;
    let target_epoch = request.target_epoch;
    let (realm_id, expected_stream) = match &request.effective_scope {
        ScopeRef::Realm { realm_id } => (
            realm_id,
            CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
        ),
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => (
            realm_id,
            CommitStreamRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: circle_id.clone(),
            },
        ),
        ScopeRef::Sidecar {
            realm_id,
            sidecar_id,
        } => (
            realm_id,
            CommitStreamRef::Sidecar {
                realm_id: realm_id.clone(),
                sidecar_id: sidecar_id.clone(),
            },
        ),
        _ => return Ok(Read::NotFound),
    };
    if realm_id != &request.realm_id {
        return Ok(Read::NotFound);
    }
    let Some(target_row) = accepted_row(conn, target_ref).await? else {
        return Ok(Read::NotFound);
    };
    let target = decode_commit(&target_row)?;
    if target.stream_ref != expected_stream
        || target.realm_id != *realm_id
        || target.event_ref != *target_ref
    {
        return Ok(Read::NotFound);
    }
    let Some(tenure) = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(realm_id.as_str())
        .get_result::<TenureRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
    else {
        return Ok(Read::NotFound);
    };
    if tenure.service_id != issuer.as_str() {
        // The Account Station may hold a verified anchored replica. A
        // governing peer read must run on the exact current authority.
        if source_peer.is_some() {
            return Ok(Read::NotFound);
        }
        let anchored = sql_query(
            "SELECT EXISTS (SELECT 1 FROM replica_stream_anchors \
             WHERE realm_id=$1 AND stream_key=$2 AND anchor_commit_id IS NOT NULL) AS present",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(crate::authority_commit::stream_key(&expected_stream)?)
        .get_result::<PresentRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .present;
        if !anchored {
            return Ok(Read::NotFound);
        }
    }
    let (joined_at_target, floor) =
        if let ScopeRef::Sidecar { sidecar_id, .. } = &request.effective_scope {
            let floor = crate::sidecar_authority_cut::public_material_floor_in_connection(
                conn, realm_id, sidecar_id, caller,
            )
            .await?;
            (
                floor
                    .as_ref()
                    .is_some_and(|floor| target.stream_position >= floor.oldest_position),
                floor,
            )
        } else if let ScopeRef::Circle { circle_id, .. } = &request.effective_scope {
            let Some(join) = sql_query(
                "SELECT membership,current_stream_position,current_commit_id \
             FROM circle_member_state_current_results WHERE realm_id=$1 AND circle_id=$2 \
             AND member_id=$3 AND membership='join' AND source_stream_ref=$4 \
             AND circle_member_parent_join_current(realm_id,member_id,value)",
            )
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(circle_id.as_str())
            .bind::<Text, _>(caller.to_string())
            .bind::<Jsonb, _>(
                serde_json::to_value(&expected_stream).map_err(PersistenceError::database)?,
            )
            .get_result::<MemberRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            else {
                return Ok(Read::NotFound);
            };
            let joined_at_target = if join.current_stream_position < 0 {
                false
            } else if target.stream_position >= join.current_stream_position as u64 {
                true
            } else {
                // The most recent membership at the target cut must itself be
                // joined and bind the parent's still-current exact revision.
                let historical = sql_query(
                    "SELECT circle_member_parent_join_current($1,$2,h.payload) AS present \
                 FROM (SELECT e.envelope->'payload' AS payload \
                 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
                 WHERE c.realm_id=$1 AND c.stream_ref=$3 AND c.stream_position <= $4 \
                 AND e.state='committed' AND e.envelope->>'kind'='ak.circle.member.state' \
                 AND e.envelope->'payload'->'member_id'=$5 \
                 ORDER BY c.stream_position DESC LIMIT 1) h",
                )
                .bind::<Text, _>(realm_id.as_str())
                .bind::<Text, _>(caller.to_string())
                .bind::<Jsonb, _>(
                    serde_json::to_value(&expected_stream).map_err(PersistenceError::database)?,
                )
                .bind::<BigInt, _>(
                    i64::try_from(target.stream_position).map_err(PersistenceError::database)?,
                )
                .bind::<Jsonb, _>(serde_json::to_value(caller).map_err(PersistenceError::database)?)
                .get_result::<PresentRow>(&mut *conn)
                .await
                .optional()
                .map_err(PersistenceError::database)?;
                historical.is_some_and(|row| row.present)
            };
            let floor = if tenure.service_id == issuer.as_str() {
                crate::account_stream_scan::caller_circle_floor_in_connection(
                    conn, realm_id, circle_id, caller,
                )
                .await?
            } else {
                match crate::account_stream_scan::replica_circle_floor_in_connection(
                    conn, realm_id, circle_id, caller,
                )
                .await?
                {
                    Ok(floor) => Some(floor),
                    Err(_) => return Ok(Read::RevisionUnavailable),
                }
            };
            (joined_at_target, floor)
        } else {
            let Some(join) = sql_query(
                "SELECT membership,current_stream_position,current_commit_id \
         FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2",
            )
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(caller.to_string())
            .get_result::<MemberRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            else {
                return Ok(Read::NotFound);
            };
            if join.membership != "join" || join.current_stream_position < 0 {
                return Ok(Read::NotFound);
            }
            let joined_at_target = target.stream_position
                >= u64::try_from(join.current_stream_position).map_err(|_| {
                    PersistenceError::Internal("stored member join position is negative".to_owned())
                })?
                || (target.stream_position == 0
                    && founding_join(conn, realm_id, &join.current_commit_id).await?);
            let floor = if tenure.service_id == issuer.as_str() {
                crate::account_stream_scan::caller_realm_floor_in_connection(conn, realm_id, caller)
                    .await?
            } else {
                match crate::account_stream_scan::replica_realm_floor_in_connection(
                    conn, realm_id, caller,
                )
                .await?
                {
                    Ok(floor) => Some(floor),
                    Err(_) => return Ok(Read::RevisionUnavailable),
                }
            };
            (joined_at_target, floor)
        };
    if !joined_at_target || floor.is_none_or(|floor| target.stream_position < floor.oldest_position)
    {
        return Ok(Read::NotFound);
    }
    if let Some(peer) = source_peer
        && !crate::account_stream_scan::peer_replication_right_at_in_connection(
            conn,
            &expected_stream,
            peer,
            target.stream_position,
        )
        .await?
    {
        return Ok(Read::NotFound);
    }
    let Some(target_event) = decode_event(&target_row)? else {
        return Ok(Read::RevisionUnavailable);
    };
    if target_event.scope_ref != request.effective_scope
        || target_event.realm_id != *realm_id
        || target_event.event_id != *target_ref
    {
        return Ok(Read::NotFound);
    }
    let target_group = match target_event.kind {
        EventKind::MlsGenesis => {
            let payload: MlsGenesisPayload = serde_json::to_value(&target_event.payload)
                .ok()
                .and_then(|value| serde_json::from_value(value).ok())
                .ok_or_else(|| PersistenceError::Internal("stored MLS Genesis invalid".into()))?;
            if target_epoch != 0 {
                return Ok(Read::NotFound);
            }
            payload.mls_group_id().map_err(|error| {
                PersistenceError::Internal(format!("stored MLS group id invalid: {error}"))
            })?
        }
        EventKind::MlsCommit => {
            let payload: arkret_models_crypto::MlsCommitPayload =
                serde_json::to_value(&target_event.payload)
                    .ok()
                    .and_then(|value| serde_json::from_value(value).ok())
                    .ok_or_else(|| {
                        PersistenceError::Internal("stored MLS Commit invalid".into())
                    })?;
            if payload.next_epoch() != target_epoch {
                return Ok(Read::NotFound);
            }
            payload.mls_group_id().map_err(|error| {
                PersistenceError::Internal(format!("stored MLS group id invalid: {error}"))
            })?
        }
        _ => return Ok(Read::NotFound),
    };
    if target_group != request.mls_group_id {
        return Ok(Read::NotFound);
    }
    // The target Event must itself be disclosed at this exact member cut;
    // this does not disclose a prejoin Genesis Event to a later member.
    let target_full = CommittedEventFullView {
        commit: target.clone(),
        event: target_event,
    };
    if !matches!(
        crate::committed_disclosure::disclose_to_member_in_connection(
            conn,
            vec![target_full],
            caller,
        )
        .await?
        .as_slice(),
        [CommittedEventView::Full(_)]
    ) {
        return Ok(Read::NotFound);
    }
    if source_peer.is_none() && tenure.service_id != issuer.as_str() {
        // A since-join Account replica has no prejoin Genesis or governance
        // mls_group current. The governing peer validates the exact Genesis
        // before returning signed public material.
        return Ok(Read::Authorized { genesis: None });
    }
    // One scope has one irreversible Genesis. The governing Station binds
    // the selected target to its exact accepted Genesis in the same read cut.
    let scope_key = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&request.effective_scope)
            .map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    let Some(group_row) =
        sql_query("SELECT mls_group_id,value FROM mls_group_current_results WHERE scope_key=$1")
            .bind::<Text, _>(&scope_key)
            .get_result::<GroupRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
    else {
        return Ok(Read::RevisionUnavailable);
    };
    let group: MlsGroupCurrent = serde_json::from_value(group_row.value).map_err(|error| {
        PersistenceError::Internal(format!("stored MLS group current is invalid: {error}"))
    })?;
    if group_row.mls_group_id != request.mls_group_id.as_str()
        || group.effective_scope != request.effective_scope
        || request
            .group_state_event_id
            .as_ref()
            .is_some_and(|selected| selected != &group.genesis_event_ref)
    {
        return Ok(Read::NotFound);
    }
    let Some(genesis_row) = accepted_row(conn, &group.genesis_event_ref).await? else {
        return Ok(Read::RevisionUnavailable);
    };
    let genesis_commit = decode_commit(&genesis_row)?;
    let Some(genesis_event) = decode_event(&genesis_row)? else {
        return Ok(Read::RevisionUnavailable);
    };
    if genesis_commit.stream_ref != expected_stream
        || genesis_commit.event_ref != group.genesis_event_ref
        || genesis_event.kind != EventKind::MlsGenesis
        || genesis_event.event_id != group.genesis_event_ref
        || genesis_event.scope_ref != request.effective_scope
        || genesis_event.realm_id != *realm_id
    {
        return Ok(Read::NotFound);
    }
    let genesis_payload: MlsGenesisPayload = serde_json::to_value(&genesis_event.payload)
        .ok()
        .and_then(|value| serde_json::from_value(value).ok())
        .ok_or_else(|| PersistenceError::Internal("stored MLS Genesis invalid".into()))?;
    if genesis_payload.mls_group_id().map_err(|error| {
        PersistenceError::Internal(format!("stored MLS group id invalid: {error}"))
    })? != request.mls_group_id
    {
        return Ok(Read::NotFound);
    }
    Ok(Read::Authorized {
        genesis: Some(Box::new(arkret_wire::CommittedEventFullView {
            commit: genesis_commit,
            event: genesis_event,
        })),
    })
}

pub(crate) async fn read(
    pool: &PgPool,
    request: &MlsGroupStateMaterialRequestBody,
    issuer: &DidCoreId,
    source_peer: Option<&DidCoreId>,
) -> PersistenceResult<Read> {
    request
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let (Some(caller_actor_id), Some(target_commit_event_ref), Some(target_epoch)) = (
        request.caller_actor_id.clone(),
        request.target_commit_event_ref.clone(),
        request.target_epoch,
    ) else {
        return Ok(Read::NotFound);
    };
    let selector = MemberMlsTargetSelector {
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request.mls_group_id.clone(),
        group_state_event_id: Some(request.group_state_event_id.clone()),
        caller_actor_id,
        target_commit_event_ref,
        target_epoch,
    };
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        read_in_connection(conn, &selector, issuer, source_peer)
            .await
            .map_err(PgTransactionError::from)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
