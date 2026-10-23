//! Registered typed-pair Strand position current storage. The value and
//! selector types come from the SDK, including the whole JSON-null value.

use arkret_models_collaboration::objects::strand::StrandPositionCurrent;
use arkret_wire::{CurrentRevision, RealmId, SpaceId, StrandId};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::{Value, json};

#[derive(diesel::QueryableByName)]
struct ObjectRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct ListRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    space_commit_id: String,
    #[diesel(sql_type = BigInt)]
    space_position: i64,
    #[diesel(sql_type = Jsonb)]
    space: Value,
    #[diesel(sql_type = BigInt)]
    parent_position: i64,
    #[diesel(sql_type = Jsonb)]
    parent: Value,
    #[diesel(sql_type = BigInt)]
    policy_position: i64,
    #[diesel(sql_type = Jsonb)]
    policy: Value,
}

const LIST_CURRENT_SQL: &str = "SELECT s.realm_id,s.current_commit_id AS space_commit_id, \
    s.current_stream_position AS space_position,s.value AS space, \
    p.current_stream_position AS parent_position,p.value AS parent, \
    c.current_stream_position AS policy_position,c.value AS policy \
    FROM space_current_results s \
    JOIN space_parent_current_results p ON p.space_id=s.space_id AND p.realm_id=s.realm_id \
    JOIN space_child_scope_policy_current_results c ON c.space_id=s.space_id AND c.realm_id=s.realm_id \
    JOIN realm_commits rc ON rc.commit_id=s.current_commit_id AND rc.realm_id=s.realm_id \
        AND rc.stream_position=s.current_stream_position \
    JOIN realm_commits pc ON pc.commit_id=p.current_commit_id AND pc.realm_id=p.realm_id \
        AND pc.stream_position=p.current_stream_position AND pc.stream_ref=rc.stream_ref \
    JOIN realm_commits qc ON qc.commit_id=c.current_commit_id AND qc.realm_id=c.realm_id \
        AND qc.stream_position=c.current_stream_position AND qc.stream_ref=rc.stream_ref \
    WHERE s.space_id=$1 AND rc.stream_ref->>'kind'='realm' \
        AND rc.stream_ref->>'realm_id'=s.realm_id FOR SHARE OF s,p,c";

#[derive(diesel::QueryableByName)]
struct PositionRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Bool)]
    covered: bool,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
    #[diesel(sql_type = BigInt)]
    invalid_count: i64,
}

fn refused(reason: &str) -> PersistenceError {
    let code = match reason {
        arkret_wire::ReasonCode::SPACE_NOT_ACTIVE => coland_storage::ConflictCode::SpaceNotActive,
        arkret_wire::ReasonCode::SPACE_REALM_MISMATCH => {
            coland_storage::ConflictCode::SpaceRealmMismatch
        }
        arkret_wire::ReasonCode::STRAND_NOT_ACTIVE => coland_storage::ConflictCode::StrandNotActive,
        _ => coland_storage::ConflictCode::FailedPrecondition,
    };
    PersistenceError::Conflict(format!("{}: {reason}", code.as_str()))
}

/// Admit a placement against the same locked Realm cut as its covering Commit.
/// The generic replica installer below only folds an already accepted value.
pub(crate) async fn commit_authority_position_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    event_approvals: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::events_payloads::strand::{
        StrandMovePayload, StrandReorderPayload,
    };
    let mut accepted_approvals = Vec::new();
    let (board, strand, destination, rank, from, expected, reorder) = match event.kind {
        arkret_wire::EventKind::StrandMove => {
            let body: StrandMovePayload = serde_json::from_value(json!(&event.payload))
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            (
                body.board_space_id,
                body.strand_id,
                body.target_space_id,
                body.rank,
                body.from_space_id,
                body.expected_position,
                false,
            )
        }
        arkret_wire::EventKind::StrandReorder => {
            let body: StrandReorderPayload = serde_json::from_value(json!(&event.payload))
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            (
                body.board_space_id,
                body.strand_id,
                body.space_id,
                body.rank,
                None,
                body.expected_position,
                true,
            )
        }
        _ => return Ok(()),
    };
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if commit.realm_id != event.realm_id
        || commit.event_ref != event.event_id
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(PersistenceError::SchemaViolation(
            "position requires its exact RealmCommit".to_owned(),
        ));
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let position =
        i64::try_from(commit.stream_position).map_err(|_| refused("position exceeds BIGINT"))?;
    let strand_row = diesel::sql_query("SELECT s.realm_id,s.current_stream_position,s.value FROM strand_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position WHERE s.strand_id=$1 AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=s.realm_id FOR SHARE OF s")
        .bind::<Text,_>(strand.as_str()).get_result::<ObjectRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| refused("placement Strand is absent"))?;
    if strand_row.realm_id != event.realm_id.as_str() {
        return Err(refused("space_realm_mismatch"));
    }
    if strand_row.current_stream_position >= position
        || strand_row.value.get("state") != Some(&json!("active"))
        || strand_row
            .value
            .get("scope_circle_id")
            .is_some_and(|v| !v.is_null())
    {
        return Err(refused("strand_not_active"));
    }
    let board_row = diesel::sql_query("SELECT s.realm_id,s.current_stream_position,s.value FROM space_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position WHERE s.space_id=$1 AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=s.realm_id FOR SHARE OF s")
        .bind::<Text,_>(board.as_str()).get_result::<ObjectRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| refused("placement Board is absent"))?;
    if board_row.realm_id != event.realm_id.as_str() {
        return Err(refused("space_realm_mismatch"));
    }
    if board_row.current_stream_position >= position
        || board_row.value.get("kind") != Some(&json!("board"))
        || board_row.value.get("state") != Some(&json!("active"))
        || board_row
            .value
            .get("scope_circle_id")
            .is_some_and(|v| !v.is_null())
    {
        return Err(refused("space_not_active"));
    }
    // Metadata, parent and child policy have independent registered writers.
    // Read them at this locked cut and prove each family's own source Commit;
    // a legal reparent need not rewrite metadata or policy at its new revision.
    let list = diesel::sql_query(LIST_CURRENT_SQL)
        .bind::<Text, _>(destination.as_str())
        .get_result::<ListRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| refused("placement List is absent or incomplete"))?;
    if list.realm_id != event.realm_id.as_str() {
        return Err(refused("space_realm_mismatch"));
    }
    if list.space_position >= position
        || list.parent_position >= position
        || list.policy_position >= position
        || list.space.get("kind") != Some(&json!("list"))
        || list.space.get("state") != Some(&json!("active"))
        || list
            .space
            .get("scope_circle_id")
            .is_some_and(|v| !v.is_null())
        || list.parent != json!({"parent_space_id":board})
    {
        return Err(refused("space_not_active"));
    }
    if list.policy != Value::Null
        && list.policy.get("kind") != Some(&json!("allow_any"))
        && list.policy.get("kind") != Some(&json!("require_same_scope"))
    {
        return Err(refused("placement child-scope policy is unresolved"));
    }
    let previous = diesel::sql_query("SELECT p.realm_id,p.current_stream_position,p.value,(c.commit_id IS NOT NULL) AS covered FROM strand_position_current_results p LEFT JOIN realm_commits c ON c.commit_id=p.current_commit_id AND c.realm_id=p.realm_id AND c.stream_position=p.current_stream_position AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=p.realm_id WHERE p.board_space_id=$1 AND p.strand_id=$2 FOR UPDATE OF p")
        .bind::<Text,_>(board.as_str()).bind::<Text,_>(strand.as_str())
        .get_result::<PositionRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if previous.as_ref().is_some_and(|row| {
        !row.covered
            || row.realm_id != event.realm_id.as_str()
            || row.current_stream_position >= position
    }) {
        return Err(refused("space_realm_mismatch"));
    }
    let current: Option<StrandPositionCurrent> = previous
        .as_ref()
        .map(|row| {
            serde_json::from_value(row.value.clone()).map_err(|error| {
                PersistenceError::Internal(format!("stored Strand position is invalid: {error}"))
            })
        })
        .transpose()?
        .flatten();
    if expected
        .as_ref()
        .is_some_and(|guard| Some(guard) != current.as_ref())
    {
        return Err(refused("strand position expected_position mismatch"));
    }
    if from
        .as_ref()
        .is_some_and(|source| current.as_ref().map(|v| &v.list_space_id) != Some(source))
    {
        return Err(refused("source List differs from current position"));
    }
    if reorder
        && current
            .as_ref()
            .is_none_or(|value| value.list_space_id != destination)
    {
        return Err(refused("reorder requires the current List"));
    }
    if let Some(source) = current.as_ref().map(|value| &value.list_space_id) {
        // A tombstoned source can be repaired by moving out, but the source
        // must still be an actual List within this Board and Realm.
        let source_row = diesel::sql_query(LIST_CURRENT_SQL)
            .bind::<Text, _>(source.as_str())
            .get_result::<ListRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .ok_or_else(|| refused("source List is absent or incomplete"))?;
        if source_row.realm_id != event.realm_id.as_str()
            || source_row.space_position >= position
            || source_row.parent_position >= position
            || source_row.policy_position >= position
            || source_row.space.get("kind") != Some(&json!("list"))
            || source_row.parent != json!({"parent_space_id":board})
            || source_row
                .space
                .get("scope_circle_id")
                .is_some_and(|v| !v.is_null())
        {
            return Err(refused("source List is not in the Board"));
        }
    }
    let (wip_override, general_approvals) =
        crate::realm_authorization_cut::authorize_strand_position_in_connection(
            conn,
            event,
            current.as_ref().map(|value| &value.list_space_id),
            &destination,
            commit,
            event_approvals,
        )
        .await?;
    accepted_approvals.extend(general_approvals);
    if !reorder {
        let fields = &list.space["fields"];
        if let Some(limit) = fields.get("wip_limit").and_then(Value::as_i64) {
            let counts = diesel::sql_query("SELECT COUNT(DISTINCT p.strand_id) FILTER (WHERE s.value->>'state' IN ('active','archived')) AS count, COUNT(*) FILTER (WHERE s.value->>'state' IS NULL OR s.value->>'state' NOT IN ('active','archived','redacted','tombstoned')) AS invalid_count FROM strand_position_current_results p JOIN strand_current_results s ON s.strand_id=p.strand_id AND s.realm_id=p.realm_id WHERE p.realm_id=$1 AND p.board_space_id=$2 AND p.value->>'list_space_id'=$3")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(board.as_str())
                .bind::<Text,_>(destination.as_str()).get_result::<CountRow>(&mut *conn).await.map_err(PersistenceError::database)?;
            if counts.invalid_count != 0 {
                return Err(refused("List WIP basis contains an unknown Strand state"));
            }
            let additional = i64::from(
                current
                    .as_ref()
                    .is_none_or(|value| value.list_space_id != destination),
            );
            if counts.count + additional > limit && !wip_override {
                match fields.get("wip_limit_enforcement").and_then(Value::as_str) {
                    Some("warn") => {
                        tracing::warn!(
                            diagnostic_key = "list_wip_limit_exceeded",
                            realm_id = %event.realm_id,
                            event_id = %event.event_id,
                            board_space_id = %board,
                            list_space_id = %destination,
                            strand_id = %strand,
                            wip_limit = limit,
                            count_after = counts.count + additional,
                            list_policy_commit_id = %list.space_commit_id,
                            list_policy_stream_position = list.space_position,
                            "Strand move attempts to exceed List WIP limit"
                        )
                    }
                    Some("reject") => {
                        return Err(refused("target List WIP limit exceeded"));
                    }
                    Some("require_review") => {
                        accepted_approvals.extend(
                            crate::approval_admission::require_list_wip(
                                conn,
                                event,
                                commit,
                                event_approvals,
                                &destination,
                                &CurrentRevision {
                                    commit_id: arkret_wire::RealmCommitId::new(
                                        &list.space_commit_id,
                                    )
                                    .map_err(|error| {
                                        PersistenceError::Internal(error.to_string())
                                    })?,
                                    stream_position: list.space_position as u64,
                                },
                            )
                            .await?,
                        );
                    }
                    _ => return Err(refused("target List WIP policy is unresolved")),
                }
            }
        }
    }
    let list_id_for_audit = destination.clone();
    install_in_connection(
        conn,
        &event.realm_id,
        &board,
        &strand,
        &CurrentRevision {
            commit_id: commit.commit_id.clone(),
            stream_position: commit.stream_position,
        },
        &Some(StrandPositionCurrent {
            list_space_id: destination,
            rank,
        }),
        commit.committed_at,
    )
    .await?;
    crate::approval_admission::consume_and_audit(
        conn,
        event,
        commit,
        &accepted_approvals,
        &json!({"list_space_id":list_id_for_audit, "list_policy_revision": {
            "commit_id":list.space_commit_id,"stream_position":list.space_position},
            "wip_override":wip_override}),
    )
    .await
}

/// Install the value of a verified snapshot or project an accepted Commit.
/// Admission checks belong to the authority writer, never this replica sink.
pub(crate) async fn install_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    board_space_id: &SpaceId,
    strand_id: &StrandId,
    revision: &CurrentRevision,
    current: &Option<StrandPositionCurrent>,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let position = i64::try_from(revision.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("position revision exceeds BIGINT".to_owned())
    })?;
    let value = serde_json::to_value(current).map_err(PersistenceError::database)?;
    let changed = diesel::sql_query(
        "INSERT INTO strand_position_current_results \
         (realm_id,board_space_id,strand_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7) \
         ON CONFLICT(board_space_id,strand_id) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE strand_position_current_results.realm_id=EXCLUDED.realm_id \
           AND (strand_position_current_results.current_stream_position<EXCLUDED.current_stream_position \
             OR (strand_position_current_results.current_stream_position=EXCLUDED.current_stream_position \
               AND strand_position_current_results.current_commit_id=EXCLUDED.current_commit_id \
               AND strand_position_current_results.value=EXCLUDED.value))",
    )
    .bind::<Text,_>(realm_id.as_str())
    .bind::<Text,_>(board_space_id.as_str())
    .bind::<Text,_>(strand_id.as_str())
    .bind::<Text,_>(revision.commit_id.as_str())
    .bind::<BigInt,_>(position)
    .bind::<Jsonb,_>(value)
    .bind::<Timestamptz,_>(at)
    .execute(conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(PersistenceError::Conflict(
            "failed_precondition: position identity belongs to another Realm or a later revision"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Fold a producer Event already covered by a verified RealmCommit. The
/// governing Station decided authorization, optional CAS and WIP; a replica
/// derives the registered value and never issues a second admission verdict.
pub(crate) async fn project_verified_event_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::events_payloads::strand::{
        StrandMovePayload, StrandReorderPayload,
    };
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let (board, strand, current) = match event.kind {
        arkret_wire::EventKind::StrandMove => {
            let body: StrandMovePayload = serde_json::from_value(payload)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            (
                body.board_space_id,
                body.strand_id,
                StrandPositionCurrent {
                    list_space_id: body.target_space_id,
                    rank: body.rank,
                },
            )
        }
        arkret_wire::EventKind::StrandReorder => {
            let body: StrandReorderPayload = serde_json::from_value(payload)
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            (
                body.board_space_id,
                body.strand_id,
                StrandPositionCurrent {
                    list_space_id: body.space_id,
                    rank: body.rank,
                },
            )
        }
        _ => return Ok(()),
    };
    if commit.realm_id != event.realm_id
        || commit.event_ref != event.event_id
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(PersistenceError::SchemaViolation(
            "position replica has a mismatched RealmCommit".to_owned(),
        ));
    }
    install_in_connection(
        conn,
        &event.realm_id,
        &board,
        &strand,
        &CurrentRevision {
            commit_id: commit.commit_id.clone(),
            stream_position: commit.stream_position,
        },
        &Some(current),
        commit.committed_at,
    )
    .await
}
