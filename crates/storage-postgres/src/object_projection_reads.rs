//! Caller-visible Space and Strand lists derived from durable current rows.
//! No mutable in-process projection is an admission or read-state source.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::objects::query_projection::{
    ProjectionAssignedToRelation, ProjectionSpaceList, ProjectionSpaceRow, ProjectionStrandList,
    ProjectionStrandRow,
};
use arkret_models_collaboration::objects::relation::Relation;
use arkret_models_collaboration::objects::space::Space;
use arkret_models_collaboration::objects::strand::{Strand, StrandPositionCurrent};
use arkret_wire::{
    ActorId, CircleId, CommitStreamRef, ObjectState, RealmId, ScopeRef, SpaceId, SpaceState,
    StrandId,
};
use coland_storage::{
    ObjectCurrentSnapshot, ObjectCurrentSnapshotStore, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Jsonb, Text};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::Value;

use crate::{PgPool, PgTransactionError};

#[derive(diesel::QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct CircleRow {
    #[diesel(sql_type = Text)]
    circle_id: String,
}

#[derive(diesel::QueryableByName)]
struct PositionRow {
    #[diesel(sql_type = Text)]
    board_space_id: String,
    #[diesel(sql_type = Text)]
    strand_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct CurrentObjectRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    proved: bool,
}

#[derive(diesel::QueryableByName)]
struct StrandSnapshotRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    source_stream_ref: Option<Value>,
}

pub struct PgObjectCurrentSnapshotStore {
    pub pool: PgPool,
}

/// A verified snapshot can cover a current row without its original Commit.
/// Match selector, revision, value and source stream against the durable cut.
pub(crate) fn current_source_sql(row: &str, selector: &str) -> String {
    format!(
        "COALESCE(\
         (SELECT proof_commit.stream_ref FROM realm_commits proof_commit \
          WHERE proof_commit.commit_id={row}.current_commit_id AND proof_commit.realm_id={row}.realm_id \
            AND proof_commit.stream_position={row}.current_stream_position), \
         (SELECT r.source_stream_ref FROM replica_authorization_rows r \
          JOIN replica_authorization_cuts cut ON cut.realm_id=r.realm_id \
            AND cut.source_stream_ref=r.source_stream_ref \
          WHERE r.realm_id={row}.realm_id AND r.selector={selector} \
            AND r.current_commit_id={row}.current_commit_id \
            AND r.current_stream_position={row}.current_stream_position \
            AND r.value={row}.value AND r.source_stream_ref->>'realm_id'=r.realm_id \
            AND r.current_stream_position<=cut.head_stream_position \
            AND (r.current_stream_position<cut.head_stream_position \
                 OR r.current_commit_id=cut.head_commit_id)))"
    )
}

/// Restart caches retain their verified snapshot provenance after the live
/// authorization cut expires. This fallback grants no current read or write
/// authority and must not be used by the canonical query paths below.
fn hydration_source_sql(row: &str, selector: &str) -> String {
    let live = current_source_sql(row, selector);
    format!(
        "COALESCE({live}, \
         (SELECT r.source_stream_ref FROM replica_authorization_rows r \
          JOIN replica_stream_anchors a ON a.realm_id=r.realm_id \
          JOIN realm_commits opening ON opening.commit_id=a.join_commit_id \
            AND opening.realm_id=a.realm_id AND opening.stream_key=a.stream_key \
            AND opening.stream_ref=r.source_stream_ref \
          WHERE r.realm_id={row}.realm_id AND r.selector={selector} \
            AND r.current_commit_id={row}.current_commit_id \
            AND r.current_stream_position={row}.current_stream_position \
            AND r.value={row}.value AND r.source_stream_ref->>'realm_id'=r.realm_id \
            AND a.anchor_commit_id IS NOT NULL \
            AND r.current_stream_position<=a.anchor_stream_position \
            AND (r.current_stream_position<a.anchor_stream_position \
                 OR r.current_commit_id=a.anchor_commit_id)))"
    )
}

#[async_trait::async_trait]
impl ObjectCurrentSnapshotStore for PgObjectCurrentSnapshotStore {
    async fn snapshot(&self) -> PersistenceResult<ObjectCurrentSnapshot> {
        let mut conn = self.pool.get().await.map_err(PersistenceError::database)?;
        let (space_rows, strand_rows) = conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn).await?;
            let orphan_sibling: crate::ExistsRow = diesel::sql_query(
                "SELECT EXISTS(SELECT 1 FROM space_parent_current_results p \
                 LEFT JOIN space_current_results s ON s.realm_id=p.realm_id AND s.space_id=p.space_id \
                 WHERE s.space_id IS NULL UNION ALL SELECT 1 FROM space_child_scope_policy_current_results c \
                 LEFT JOIN space_current_results s ON s.realm_id=c.realm_id AND s.space_id=c.space_id \
                 WHERE s.space_id IS NULL) AS present",
            ).get_result(&mut *conn).await?;
            if orphan_sibling.present {
                return Err(corrupt("Space current has orphan sibling family").into());
            }
            let realm_source = "jsonb_build_object('kind','realm','realm_id',s.realm_id)";
            let space_source = hydration_source_sql("s", "jsonb_build_object('kind','space','space_id',s.space_id)");
            let parent_source = hydration_source_sql("p", "jsonb_build_object('kind','space_parent','space_id',p.space_id)");
            let policy_source = hydration_source_sql("c", "jsonb_build_object('kind','space_child_scope_policy','space_id',c.space_id)");
            let spaces = diesel::sql_query(format!(
                "SELECT s.space_id AS id,s.realm_id, \
                 s.value || jsonb_build_object('parent_space_id',p.value->'parent_space_id', \
                 'child_scope_policy',c.value) AS value, \
                 (COALESCE({space_source}={realm_source},false) \
                   AND COALESCE({parent_source}={realm_source},false) \
                   AND COALESCE({policy_source}={realm_source},false) \
                   AND NOT (s.value ? 'parent_space_id') AND NOT (s.value ? 'child_scope_policy') \
                   AND jsonb_typeof(p.value)='object' AND p.value ? 'parent_space_id' \
                   AND p.value - 'parent_space_id'='{{}}'::jsonb) AS proved \
                 FROM space_current_results s \
                 LEFT JOIN space_parent_current_results p ON p.realm_id=s.realm_id AND p.space_id=s.space_id \
                 LEFT JOIN space_child_scope_policy_current_results c ON c.realm_id=s.realm_id AND c.space_id=s.space_id \
                 ORDER BY s.realm_id,s.space_id",
            )).load::<CurrentObjectRow>(&mut *conn).await?;
            let strand_source = hydration_source_sql("s", "jsonb_build_object('kind','strand','strand_id',s.strand_id)");
            let strands = diesel::sql_query(format!(
                "SELECT s.strand_id AS id,s.realm_id,s.value, \
                 {strand_source} AS source_stream_ref FROM strand_current_results s \
                 ORDER BY s.realm_id,s.strand_id",
            )).load::<StrandSnapshotRow>(&mut *conn).await?;
            Ok((spaces,strands))
        }).await.map_err(PgTransactionError::into_persistence)?;
        let spaces = space_rows
            .into_iter()
            .map(|row| {
                if !row.proved {
                    return Err(corrupt("Space current sibling has no covering RealmCommit"));
                }
                let space: Space =
                    serde_json::from_value(row.value).map_err(PersistenceError::database)?;
                if space.id.as_ref().is_none_or(|id| id.as_str() != row.id)
                    || space.realm_id.as_str() != row.realm_id
                {
                    return Err(corrupt("Space current identity mismatch"));
                }
                Ok(space)
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        let strands = strand_rows
            .into_iter()
            .map(|row| {
                let strand: Strand =
                    serde_json::from_value(row.value).map_err(PersistenceError::database)?;
                if strand.id.as_ref().is_none_or(|id| id.as_str() != row.id)
                    || strand.realm_id.as_str() != row.realm_id
                {
                    return Err(corrupt("Strand current identity mismatch"));
                }
                let expected_stream_ref = match &strand.scope_circle_id {
                    Some(circle_id) => CommitStreamRef::Circle {
                        realm_id: strand.realm_id.clone(),
                        circle_id: circle_id.clone(),
                    },
                    None => CommitStreamRef::Realm {
                        realm_id: strand.realm_id.clone(),
                    },
                };
                let source_stream_ref = row
                    .source_stream_ref
                    .ok_or_else(|| corrupt("Strand current has no covering RealmCommit"))?;
                let source_stream_ref: CommitStreamRef = serde_json::from_value(source_stream_ref)
                    .map_err(|_| corrupt("Strand current has invalid source stream"))?;
                if source_stream_ref != expected_stream_ref {
                    return Err(corrupt("Strand current source stream mismatches its scope"));
                }
                Ok(strand)
            })
            .collect::<PersistenceResult<Vec<_>>>()?;
        Ok(ObjectCurrentSnapshot { spaces, strands })
    }
}

fn corrupt(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Internal(format!("invalid projection current: {}", detail.into()))
}

fn visible(circle: Option<&CircleId>, circles: &BTreeSet<CircleId>) -> bool {
    circle.is_none_or(|id| circles.contains(id))
}

pub(crate) async fn lists_for_actor(
    pool: &PgPool,
    realm_id: &RealmId,
    actor: &ActorId,
    include_terminal: bool,
) -> PersistenceResult<Option<(ProjectionSpaceList, ProjectionStrandList)>> {
    let mut conn = pool.get().await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn).await?;
        let joined: Option<ValueRow> = diesel::sql_query(
            "SELECT value FROM member_state_current_results \
             WHERE realm_id=$1 AND member_id=$2 AND membership='join'",
        ).bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(actor.to_string())
            .get_result(&mut *conn).await.optional()?;
        if joined.is_none() { return Ok(None); }
        if joined.as_ref().is_some_and(|row| row.value != serde_json::json!({"membership":"join"})) {
            return Err(corrupt("member current value disagrees with joined state").into());
        }
        let terminal = diesel::sql_query(
            "SELECT EXISTS(SELECT 1 FROM realm_bootstrap_current_results \
             WHERE realm_id=$1 AND result_family IN ('realm_tombstone','realm_destroy')) AS present",
        ).bind::<Text,_>(realm_id.as_str()).get_result::<crate::ExistsRow>(&mut *conn).await?;
        if terminal.present {
            return Ok(Some((
                ProjectionSpaceList { realm_id: realm_id.clone(), total: 0, spaces: Vec::new(), next_cursor: None, has_more: false },
                ProjectionStrandList { realm_id: realm_id.clone(), total: 0, strands: Vec::new(), next_cursor: None, has_more: false },
            )));
        }
        let circle_rows = diesel::sql_query(
            "SELECT m.circle_id FROM circle_member_state_current_results m \
             JOIN circle_current_results c ON c.circle_id=m.circle_id AND c.realm_id=m.realm_id \
             JOIN realm_commits rc ON rc.commit_id=m.current_commit_id \
               AND rc.realm_id=m.realm_id AND rc.stream_position=m.current_stream_position \
               AND rc.stream_ref=m.source_stream_ref \
             WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join' \
               AND circle_member_parent_join_current(m.realm_id,m.member_id,m.value) \
               AND c.value->>'state'='active' \
               AND m.source_stream_ref->>'circle_id'=m.circle_id",
        ).bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(actor.to_string())
            .load::<CircleRow>(&mut *conn).await?;
        let circles = circle_rows.into_iter().map(|row| row.circle_id.parse::<CircleId>()
            .map_err(|error| corrupt(error.to_string()))).collect::<PersistenceResult<BTreeSet<_>>>()?;
        let incomplete_space = diesel::sql_query(
            "SELECT EXISTS(SELECT 1 FROM space_current_results s \
             LEFT JOIN space_parent_current_results p ON p.realm_id=s.realm_id AND p.space_id=s.space_id \
             LEFT JOIN space_child_scope_policy_current_results c ON c.realm_id=s.realm_id AND c.space_id=s.space_id \
             WHERE s.realm_id=$1 AND (p.space_id IS NULL OR c.space_id IS NULL \
               OR s.value ? 'parent_space_id' OR s.value ? 'child_scope_policy' \
               OR jsonb_typeof(p.value)<>'object' OR NOT p.value ? 'parent_space_id' \
               OR p.value - 'parent_space_id' <> '{}'::jsonb)) \
             OR EXISTS(SELECT 1 FROM space_parent_current_results p \
               LEFT JOIN space_current_results s ON s.realm_id=p.realm_id AND s.space_id=p.space_id \
               WHERE p.realm_id=$1 AND s.space_id IS NULL) \
             OR EXISTS(SELECT 1 FROM space_child_scope_policy_current_results c \
               LEFT JOIN space_current_results s ON s.realm_id=c.realm_id AND s.space_id=c.space_id \
               WHERE c.realm_id=$1 AND s.space_id IS NULL) AS present",
        ).bind::<Text,_>(realm_id.as_str()).get_result::<crate::ExistsRow>(&mut *conn).await?;
        if incomplete_space.present {
            return Err(corrupt("Space registered sibling families are incomplete or conflicting").into());
        }
        let space_rows = diesel::sql_query(
            "SELECT s.value || jsonb_build_object('parent_space_id',p.value->'parent_space_id', \
             'child_scope_policy',c.value) AS value FROM space_current_results s \
             JOIN space_parent_current_results p ON p.realm_id=s.realm_id AND p.space_id=s.space_id \
             JOIN space_child_scope_policy_current_results c ON c.realm_id=s.realm_id AND c.space_id=s.space_id \
             WHERE s.realm_id=$1 ORDER BY s.space_id",
        ).bind::<Text,_>(realm_id.as_str()).load::<ValueRow>(&mut *conn).await?;
        let mut spaces = Vec::new();
        let mut space_objects = BTreeMap::new();
        for row in space_rows {
            let space: Space = serde_json::from_value(row.value).map_err(PersistenceError::database)?;
            if space.realm_id != *realm_id { return Err(corrupt("Space Realm mismatch").into()); }
            let space_id = space.id.clone().ok_or_else(|| corrupt("Space id absent"))?;
            space_objects.insert(space_id, space.clone());
            if !visible(space.scope_circle_id.as_ref(), &circles) { continue; }
            let state = space.state.ok_or_else(|| corrupt("Space state absent"))?;
            if !include_terminal && state == SpaceState::Tombstoned { continue; }
            spaces.push(ProjectionSpaceRow {
                space_id: space.id.ok_or_else(|| corrupt("Space id absent"))?,
                realm_id: space.realm_id, kind: space.kind, title: space.title,
                encrypted_metadata: space.encrypted_metadata,
                parent_space_id: space.parent_space_id, rank: space.rank, state,
                state_changed_at: space.state_changed_at,
                created_by: Some(space.created_by), created_at: Some(space.created_at), updated_at: space.updated_at,
            });
        }
        let default: Option<ValueRow> = diesel::sql_query(
            "SELECT value FROM realm_set_default_strand_current_results WHERE realm_id=$1",
        ).bind::<Text,_>(realm_id.as_str()).get_result(&mut *conn).await.optional()?;
        let default = default.map(|row| serde_json::from_value::<Option<StrandId>>(
            row.value.get("default_strand_id").cloned().ok_or_else(|| corrupt("default Strand pointer absent"))?
        ).map_err(PersistenceError::database)).transpose()?.flatten();
        let mut assignments: BTreeMap<StrandId, Vec<ProjectionAssignedToRelation>> = BTreeMap::new();
        let relations = diesel::sql_query(
            "SELECT value FROM relation_current_results WHERE realm_id=$1 AND state='active' \
             AND value->>'relation_kind'='assigned_to' ORDER BY relation_id",
        ).bind::<Text,_>(realm_id.as_str()).load::<ValueRow>(&mut *conn).await?;
        for row in relations {
            let relation: Relation = serde_json::from_value(row.value).map_err(PersistenceError::database)?;
            if relation.realm_id != *realm_id || !visible(relation.scope_circle_id.as_ref(), &circles) { continue; }
            if relation.effective_scope.as_ref().is_some_and(|scope| match scope {
                ScopeRef::Realm { realm_id: id } => id != realm_id,
                ScopeRef::Circle { realm_id: id, circle_id } => id != realm_id || !circles.contains(circle_id),
                _ => true,
            }) { continue; }
            let source = relation.from_ref.as_object_ref().ok_or_else(|| corrupt("assignment source is not an object"))?;
            let strand = source.parse::<StrandId>().map_err(|error| corrupt(error.to_string()))?;
            assignments.entry(strand).or_default().push(ProjectionAssignedToRelation {
                relation_id: relation.id.ok_or_else(|| corrupt("assignment id absent"))?,
                actor_id: relation.to_ref.as_actor_id().ok_or_else(|| corrupt("assignment target is not an Actor"))?.clone(),
            });
        }
        let position_source = current_source_sql("p", "jsonb_build_object('kind','strand_position','board_space_id',p.board_space_id,'strand_id',p.strand_id)");
        let unproved_position = diesel::sql_query(format!(
            "SELECT EXISTS(SELECT 1 FROM strand_position_current_results p \
             WHERE p.realm_id=$1 AND NOT COALESCE(\
               {position_source}=jsonb_build_object('kind','realm','realm_id',p.realm_id),false)) AS present",
        )).bind::<Text,_>(realm_id.as_str()).get_result::<crate::ExistsRow>(&mut *conn).await?;
        if unproved_position.present {
            return Err(corrupt("position current has no covering RealmCommit").into());
        }
        let position_rows = diesel::sql_query(
            "SELECT board_space_id,strand_id,value FROM strand_position_current_results \
             WHERE realm_id=$1 ORDER BY strand_id,board_space_id",
        ).bind::<Text,_>(realm_id.as_str()).load::<PositionRow>(&mut *conn).await?;
        let mut positions: BTreeMap<StrandId, Vec<(SpaceId, StrandPositionCurrent)>> = BTreeMap::new();
        for row in position_rows {
            let board = row.board_space_id.parse::<SpaceId>().map_err(|error| corrupt(error.to_string()))?;
            let strand = row.strand_id.parse::<StrandId>().map_err(|error| corrupt(error.to_string()))?;
            let value = serde_json::from_value::<Option<StrandPositionCurrent>>(row.value).map_err(PersistenceError::database)?;
            if let Some(value) = value { positions.entry(strand).or_default().push((board, value)); }
        }
        let strand_rows = diesel::sql_query(
            "SELECT value FROM strand_current_results WHERE realm_id=$1 ORDER BY strand_id",
        ).bind::<Text,_>(realm_id.as_str()).load::<ValueRow>(&mut *conn).await?;
        let mut strands = Vec::new();
        for row in strand_rows {
            let strand: Strand = serde_json::from_value(row.value).map_err(PersistenceError::database)?;
            if strand.realm_id != *realm_id { return Err(corrupt("Strand Realm mismatch").into()); }
            if !visible(strand.scope_circle_id.as_ref(), &circles) { continue; }
            let state = strand.state.ok_or_else(|| corrupt("Strand state absent"))?;
            if !include_terminal && state == ObjectState::Redacted { continue; }
            let id = strand.id.ok_or_else(|| corrupt("Strand id absent"))?;
            let mut placement = None;
            for (board_id, position) in positions.remove(&id).unwrap_or_default() {
                let board = space_objects.get(&board_id).ok_or_else(|| corrupt("position Board metadata absent"))?;
                let list = space_objects.get(&position.list_space_id).ok_or_else(|| corrupt("position List metadata absent"))?;
                if !visible(board.scope_circle_id.as_ref(), &circles) || !visible(list.scope_circle_id.as_ref(), &circles) { continue; }
                if board.kind != "board" || list.kind != "list"
                    || strand.scope_circle_id != board.scope_circle_id || strand.scope_circle_id != list.scope_circle_id {
                    return Err(corrupt("position cannot form an available structural placement").into());
                }
                // Canonical position survives independently of target lifecycle.
                // A terminal target suppresses the derived edge, never the row.
                if board.state == Some(SpaceState::Tombstoned) || list.state == Some(SpaceState::Tombstoned) {
                    continue;
                }
                if list.parent_space_id.as_ref() != Some(&board_id) {
                    return Err(corrupt("position List is not a child of its Board").into());
                }
                if placement.is_some() {
                    return Err(corrupt("Strand has multiple visible Board placements; this row cannot select one").into());
                }
                placement = Some((board_id, position));
            }
            let assigned = assignments.remove(&id).unwrap_or_default();
            let mut actors = assigned.iter().map(|row| row.actor_id.clone()).collect::<Vec<_>>();
            actors.sort_by_key(ToString::to_string); actors.dedup();
            strands.push(ProjectionStrandRow {
                is_default: default.as_ref() == Some(&id), strand_id: id,
                realm_id: strand.realm_id, state, state_changed_at: strand.state_changed_at,
                stage: strand.stage, stage_changed_at: strand.stage_changed_at,
                title: strand.metadata.as_ref().and_then(|metadata| metadata.title.clone()),
                summary: strand.metadata.as_ref().and_then(|metadata| metadata.summary.clone()),
                topic: strand.topic,
                board_space_id: placement.as_ref().map(|(board, _)| board.clone()),
                list_space_id: placement.as_ref().map(|(_, position)| position.list_space_id.clone()),
                rank: placement.map(|(_, position)| position.rank),
                assigned_actor_ids: actors, assigned_to_relations: assigned,
                created_by: Some(strand.created_by), created_at: Some(strand.created_at),
                updated_by: strand.updated_by, updated_at: strand.updated_at,
            });
        }
        Ok(Some((
            ProjectionSpaceList { realm_id: realm_id.clone(), total: spaces.len() as u64, spaces, next_cursor: None, has_more: false },
            ProjectionStrandList { realm_id: realm_id.clone(), total: strands.len() as u64, strands, next_cursor: None, has_more: false },
        )))
    }).await.map_err(PgTransactionError::into_persistence)
}

/// The effective scope of a non-terminal Strand that `actor` currently reads,
/// from durable current rows at one cut: the actor is a current joined member
/// (governed here or held as a verified replica) and, for a Circle-scoped
/// Strand, a current joined member of that active Circle. Every hidden,
/// missing or terminal target is the same `None`.
pub(crate) async fn visible_strand_scope_for_actor(
    pool: &PgPool,
    realm_id: &RealmId,
    strand_id: &StrandId,
    actor: &ActorId,
) -> PersistenceResult<Option<ScopeRef>> {
    let mut conn = pool.get().await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        if !crate::authority_commit::accepted_current_member_joined_in_connection(
            conn, realm_id, actor,
        )
        .await?
        {
            return Ok(None);
        }
        let row: Option<ValueRow> = diesel::sql_query(
            "SELECT value FROM strand_current_results WHERE realm_id=$1 AND strand_id=$2",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(strand_id.as_str())
        .get_result(&mut *conn)
        .await
        .optional()?;
        let Some(row) = row else {
            return Ok(None);
        };
        let strand: Strand =
            serde_json::from_value(row.value).map_err(PersistenceError::database)?;
        if strand.realm_id != *realm_id || strand.id.as_ref() != Some(strand_id) {
            return Err(corrupt("Strand current identity disagrees with its row").into());
        }
        if strand.state.ok_or_else(|| corrupt("Strand state absent"))? == ObjectState::Redacted {
            return Ok(None);
        }
        let Some(circle_id) = strand.scope_circle_id else {
            return Ok(Some(ScopeRef::Realm {
                realm_id: realm_id.clone(),
            }));
        };
        let joined = diesel::sql_query(
            "SELECT EXISTS(SELECT 1 FROM circle_member_state_current_results m \
             JOIN circle_current_results c ON c.circle_id=m.circle_id AND c.realm_id=m.realm_id \
             JOIN realm_commits rc ON rc.commit_id=m.current_commit_id \
               AND rc.realm_id=m.realm_id AND rc.stream_position=m.current_stream_position \
               AND rc.stream_ref=m.source_stream_ref \
             WHERE m.realm_id=$1 AND m.circle_id=$2 AND m.member_id=$3 AND m.membership='join' \
               AND circle_member_parent_join_current(m.realm_id,m.member_id,m.value) \
               AND c.value->>'state'='active' \
               AND m.source_stream_ref->>'circle_id'=m.circle_id) AS present",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(circle_id.as_str())
        .bind::<Text, _>(actor.to_string())
        .get_result::<crate::ExistsRow>(&mut *conn)
        .await?;
        Ok(joined.present.then(|| ScopeRef::Circle {
            realm_id: realm_id.clone(),
            circle_id,
        }))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

use diesel::OptionalExtension as _;

#[cfg(test)]
mod tests {
    use arkret_wire::{
        CommitStreamHead, CurrentRevision, CurrentSelector, RealmCommitId, TypedCurrentRow,
    };
    use diesel::sql_types::{BigInt, Timestamptz};

    use super::*;

    #[tokio::test]
    async fn snapshot_restore_requires_exact_verified_current_without_local_commit() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let realm = RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap();
        let id = StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap();
        let actor = ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:watcher.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let strand = Strand::new(id.clone(), realm.clone(), "verified replica", actor);
        let value = serde_json::to_value(&strand).unwrap();
        let revision = CurrentRevision {
            commit_id: RealmCommitId::from_digest([7; 32]),
            stream_position: 3,
        };
        let head = CommitStreamHead {
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            commit_id: revision.commit_id.clone(),
            stream_position: revision.stream_position,
        };
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("INSERT INTO strand_current_results(realm_id,strand_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6)")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(id.as_str())
            .bind::<Text,_>(revision.commit_id.as_str()).bind::<BigInt,_>(revision.stream_position as i64)
            .bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(chrono::Utc::now())
            .execute(&mut *conn).await.unwrap();
        let store = PgObjectCurrentSnapshotStore { pool: pool.clone() };
        assert!(
            store.snapshot().await.is_err(),
            "a row alone is not verified provenance"
        );
        crate::replica_authorization::install_verified_head(&mut conn, &head, chrono::Utc::now())
            .await
            .unwrap();
        assert!(
            store.snapshot().await.is_err(),
            "a head alone does not prove the current value"
        );
        let entry = TypedCurrentRow::Value {
            selector: CurrentSelector::Strand {
                strand_id: id.clone(),
            },
            source_stream_ref: head.stream_ref.clone(),
            revision: revision.clone(),
            value: value.clone(),
        };
        crate::replica_authorization::save_row(&mut conn, &realm, &entry, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(
            store.snapshot().await.unwrap().strands[0].id.as_ref(),
            Some(&id)
        );

        diesel::sql_query("UPDATE strand_current_results SET value=jsonb_set(value,'{metadata,title}','\"forged\"') WHERE strand_id=$1")
            .bind::<Text,_>(id.as_str()).execute(&mut *conn).await.unwrap();
        assert!(
            store.snapshot().await.is_err(),
            "verified evidence cannot cover another value"
        );
        diesel::sql_query("UPDATE strand_current_results SET value=$2 WHERE strand_id=$1")
            .bind::<Text, _>(id.as_str())
            .bind::<Jsonb, _>(&value)
            .execute(&mut *conn)
            .await
            .unwrap();
        diesel::sql_query(
            "UPDATE replica_authorization_cuts SET head_commit_id=$2 WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm.as_str())
        .bind::<Text, _>(RealmCommitId::from_digest([8; 32]).as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
        assert!(
            store.snapshot().await.is_err(),
            "equal-position evidence must bind the exact cut Commit"
        );
        diesel::sql_query("UPDATE replica_authorization_cuts SET head_commit_id=$2,head_stream_position=2 WHERE realm_id=$1")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(head.commit_id.as_str())
            .execute(&mut *conn).await.unwrap();
        assert!(
            store.snapshot().await.is_err(),
            "a current revision above the cut is unproved"
        );

        // A revoked live cut cannot erase the already verified bootstrap
        // provenance or prevent the entire Station from restarting.
        diesel::sql_query("DELETE FROM replica_authorization_cuts WHERE realm_id=$1")
            .bind::<Text, _>(realm.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        let source = serde_json::to_value(&head.stream_ref).unwrap();
        let opening_id = RealmCommitId::from_digest([9; 32]);
        let key = crate::authority_commit::stream_key(&head.stream_ref).unwrap();
        diesel::sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,governance_generation,commit_json,committed_at) VALUES($1,$2,$3,$4,0,0,$5,$6)")
            .bind::<Text,_>(opening_id.as_str()).bind::<Text,_>(realm.as_str())
            .bind::<Text,_>(&key).bind::<Jsonb,_>(&source)
            .bind::<Jsonb,_>(serde_json::json!({"stream_ref":source}))
            .bind::<Timestamptz,_>(chrono::Utc::now())
            .execute(&mut *conn).await.unwrap();
        diesel::sql_query("INSERT INTO replica_stream_anchors(stream_key,realm_id,join_commit_id,member_account_id,anchor_commit_id,anchor_stream_position,anchored_at) VALUES($1,$2,$3,'{}'::jsonb,$4,$5,$6)")
            .bind::<Text,_>(&key).bind::<Text,_>(realm.as_str())
            .bind::<Text,_>(opening_id.as_str()).bind::<Text,_>(head.commit_id.as_str())
            .bind::<BigInt,_>(head.stream_position as i64)
            .bind::<Timestamptz,_>(chrono::Utc::now())
            .execute(&mut *conn).await.unwrap();
        assert_eq!(
            store.snapshot().await.unwrap().strands[0].id.as_ref(),
            Some(&id)
        );
        assert!(
            crate::replica_authorization::verified_head(&mut conn, &head.stream_ref)
                .await
                .unwrap()
                .is_none()
        );
        let live = current_source_sql(
            "s",
            "jsonb_build_object('kind','strand','strand_id',s.strand_id)",
        );
        let live_read: crate::ExistsRow = diesel::sql_query(format!(
            "SELECT EXISTS(SELECT 1 FROM strand_current_results s WHERE s.realm_id=$1 AND {live} IS NOT NULL) AS present"
        )).bind::<Text,_>(realm.as_str()).get_result(&mut *conn).await.unwrap();
        assert!(
            !live_read.present,
            "historical cache evidence cannot restore a live cut"
        );

        diesel::sql_query("UPDATE strand_current_results SET value=jsonb_set(value,'{metadata,title}','\"forged\"') WHERE strand_id=$1")
            .bind::<Text,_>(id.as_str()).execute(&mut *conn).await.unwrap();
        assert!(
            store.snapshot().await.is_err(),
            "an anchor cannot cover another value"
        );
        diesel::sql_query("UPDATE strand_current_results SET value=$2 WHERE strand_id=$1")
            .bind::<Text, _>(id.as_str())
            .bind::<Jsonb, _>(&value)
            .execute(&mut *conn)
            .await
            .unwrap();
        diesel::sql_query(
            "UPDATE replica_stream_anchors SET anchor_commit_id=$2 WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm.as_str())
        .bind::<Text, _>(opening_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap();
        assert!(
            store.snapshot().await.is_err(),
            "equal-position provenance requires the exact anchored Commit"
        );
        diesel::sql_query("UPDATE replica_stream_anchors SET anchor_commit_id=NULL,anchor_stream_position=NULL,anchored_at=NULL WHERE realm_id=$1")
            .bind::<Text,_>(realm.as_str()).execute(&mut *conn).await.unwrap();
        assert!(
            store.snapshot().await.is_err(),
            "pending bootstrap is not verified cache provenance"
        );
    }
}
