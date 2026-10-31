//! Caller-visible Space and Strand lists derived from durable current rows.
//! No mutable in-process projection is an admission or read-state source.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::objects::query_projection::{
    ProjectionAssignedToRelation, SpacePage, SpaceView, StrandPage, StrandView,
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
use diesel_async::AsyncConnection;
use horme::RunQueryDsl;
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
                "SELECT EXISTS(SELECT 1 FROM space_parent_current_states p \
                 LEFT JOIN space_current_states s ON s.realm_id=p.realm_id AND s.space_id=p.space_id \
                 WHERE s.space_id IS NULL UNION ALL SELECT 1 FROM space_child_scope_policy_current_states c \
                 LEFT JOIN space_current_states s ON s.realm_id=c.realm_id AND s.space_id=c.space_id \
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
                 FROM space_current_states s \
                 LEFT JOIN space_parent_current_states p ON p.realm_id=s.realm_id AND p.space_id=s.space_id \
                 LEFT JOIN space_child_scope_policy_current_states c ON c.realm_id=s.realm_id AND c.space_id=s.space_id \
                 ORDER BY s.realm_id,s.space_id",
            )).load::<CurrentObjectRow>(&mut *conn).await?;
            let strand_source = hydration_source_sql("s", "jsonb_build_object('kind','strand','strand_id',s.strand_id)");
            let strands = diesel::sql_query(format!(
                "SELECT s.strand_id AS id,s.realm_id,s.value, \
                 {strand_source} AS source_stream_ref FROM strand_current_states s \
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
) -> PersistenceResult<Option<(SpacePage, StrandPage)>> {
    let mut conn = pool.get().await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        lists_for_actor_in_connection(conn, realm_id, actor, include_terminal).await
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// Rebuild exact public output on the caller's already held database cut.
pub(crate) async fn lists_for_actor_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    realm_id: &RealmId,
    actor: &ActorId,
    include_terminal: bool,
) -> Result<Option<(SpacePage, StrandPage)>, PgTransactionError> {
    if !crate::authority_commit::accepted_current_member_joined_in_connection(conn, realm_id, actor)
        .await?
    {
        return Ok(None);
    }
    let terminal = diesel::sql_query(
        "SELECT EXISTS(SELECT 1 FROM realm_bootstrap_current_states \
             WHERE realm_id=$1 AND state_family IN ('realm_tombstone','realm_destroy')) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<crate::ExistsRow>(&mut *conn)
    .await?;
    if terminal.present {
        return Ok(Some((
            SpacePage {
                realm_id: realm_id.clone(),
                total_count: 0,
                spaces: Vec::new(),
                next_cursor: None,
                has_more: false,
            },
            StrandPage {
                realm_id: realm_id.clone(),
                total_count: 0,
                strands: Vec::new(),
                next_cursor: None,
                has_more: false,
            },
        )));
    }
    crate::circle_current_states::require_actor_currents_in_connection(conn, Some(realm_id), actor)
        .await?;
    let circle_rows = diesel::sql_query(
        "SELECT m.circle_id FROM circle_member_state_current_states m \
             JOIN circle_current_states c ON c.circle_id=m.circle_id AND c.realm_id=m.realm_id \
             WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join' \
               AND circle_member_parent_join_current(m.realm_id,m.member_id,m.value) \
               AND circle_current_row_proved(m.realm_id,jsonb_build_object('kind','circle_member_state','circle_id',m.circle_id,'member_actor_id',m.member_id::jsonb),m.source_stream_ref,m.current_commit_id,m.current_stream_position,m.value) \
               AND circle_current_row_proved(c.realm_id,jsonb_build_object('kind','circle','circle_id',c.circle_id),c.source_stream_ref,c.current_commit_id,c.current_stream_position,c.value) \
               AND c.value->>'state'='active' \
               AND m.source_stream_ref->>'circle_id'=m.circle_id",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(actor.to_string())
    .load::<CircleRow>(&mut *conn)
    .await?;
    let circles = circle_rows
        .into_iter()
        .map(|row| {
            row.circle_id
                .parse::<CircleId>()
                .map_err(|error| corrupt(error.to_string()))
        })
        .collect::<PersistenceResult<BTreeSet<_>>>()?;
    let incomplete_space = diesel::sql_query(
            "SELECT EXISTS(SELECT 1 FROM space_current_states s \
             LEFT JOIN space_parent_current_states p ON p.realm_id=s.realm_id AND p.space_id=s.space_id \
             LEFT JOIN space_child_scope_policy_current_states c ON c.realm_id=s.realm_id AND c.space_id=s.space_id \
             WHERE s.realm_id=$1 AND (p.space_id IS NULL OR c.space_id IS NULL \
               OR s.value ? 'parent_space_id' OR s.value ? 'child_scope_policy' \
               OR jsonb_typeof(p.value)<>'object' OR NOT p.value ? 'parent_space_id' \
               OR p.value - 'parent_space_id' <> '{}'::jsonb)) \
             OR EXISTS(SELECT 1 FROM space_parent_current_states p \
               LEFT JOIN space_current_states s ON s.realm_id=p.realm_id AND s.space_id=p.space_id \
               WHERE p.realm_id=$1 AND s.space_id IS NULL) \
             OR EXISTS(SELECT 1 FROM space_child_scope_policy_current_states c \
               LEFT JOIN space_current_states s ON s.realm_id=c.realm_id AND s.space_id=c.space_id \
               WHERE c.realm_id=$1 AND s.space_id IS NULL) AS present",
        ).bind::<Text,_>(realm_id.as_str()).get_result::<crate::ExistsRow>(&mut *conn).await?;
    if incomplete_space.present {
        return Err(
            corrupt("Space registered sibling families are incomplete or conflicting").into(),
        );
    }
    let space_rows = diesel::sql_query(
            "SELECT s.value || jsonb_build_object('parent_space_id',p.value->'parent_space_id', \
             'child_scope_policy',c.value) AS value FROM space_current_states s \
             JOIN space_parent_current_states p ON p.realm_id=s.realm_id AND p.space_id=s.space_id \
             JOIN space_child_scope_policy_current_states c ON c.realm_id=s.realm_id AND c.space_id=s.space_id \
             WHERE s.realm_id=$1 ORDER BY s.space_id",
        ).bind::<Text,_>(realm_id.as_str()).load::<ValueRow>(&mut *conn).await?;
    let mut spaces = Vec::new();
    let mut space_objects = BTreeMap::new();
    for row in space_rows {
        let space: Space = serde_json::from_value(row.value).map_err(PersistenceError::database)?;
        if space.realm_id != *realm_id {
            return Err(corrupt("Space Realm mismatch").into());
        }
        let space_id = space.id.clone().ok_or_else(|| corrupt("Space id absent"))?;
        space_objects.insert(space_id, space.clone());
        if !visible(space.scope_circle_id.as_ref(), &circles) {
            continue;
        }
        let state = space.state.ok_or_else(|| corrupt("Space state absent"))?;
        if !include_terminal && state == SpaceState::Tombstoned {
            continue;
        }
        spaces.push(SpaceView {
            space_id: space.id.ok_or_else(|| corrupt("Space id absent"))?,
            realm_id: space.realm_id,
            kind: space.kind,
            title: space.title,
            encrypted_metadata: space.encrypted_metadata,
            parent_space_id: space.parent_space_id,
            rank: space.rank,
            state,
            state_changed_at: space.state_changed_at,
            created_by: Some(space.created_by),
            created_at: Some(space.created_at),
            updated_at: space.updated_at,
        });
    }
    let default: Option<ValueRow> = diesel::sql_query(
        "SELECT value FROM realm_set_default_strand_current_states WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result(&mut *conn)
    .await
    .optional()?;
    let default = default
        .map(|row| {
            serde_json::from_value::<Option<StrandId>>(
                row.value
                    .get("default_strand_id")
                    .cloned()
                    .ok_or_else(|| corrupt("default Strand pointer absent"))?,
            )
            .map_err(PersistenceError::database)
        })
        .transpose()?
        .flatten();
    let mut assignments: BTreeMap<StrandId, Vec<ProjectionAssignedToRelation>> = BTreeMap::new();
    let relations = diesel::sql_query(
        "SELECT value FROM relation_current_states WHERE realm_id=$1 AND state='active' \
             AND value->>'relation_kind'='assigned_to' ORDER BY relation_id",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<ValueRow>(&mut *conn)
    .await?;
    for row in relations {
        let relation: Relation =
            serde_json::from_value(row.value).map_err(PersistenceError::database)?;
        if relation.realm_id != *realm_id || !visible(relation.scope_circle_id.as_ref(), &circles) {
            continue;
        }
        if relation
            .effective_scope
            .as_ref()
            .is_some_and(|scope| match scope {
                ScopeRef::Realm { realm_id: id } => id != realm_id,
                ScopeRef::Circle {
                    realm_id: id,
                    circle_id,
                } => id != realm_id || !circles.contains(circle_id),
                _ => true,
            })
        {
            continue;
        }
        let source = relation
            .from_ref
            .as_object_ref()
            .ok_or_else(|| corrupt("assignment source is not an object"))?;
        let strand = source
            .parse::<StrandId>()
            .map_err(|error| corrupt(error.to_string()))?;
        assignments
            .entry(strand)
            .or_default()
            .push(ProjectionAssignedToRelation {
                relation_id: relation.id.ok_or_else(|| corrupt("assignment id absent"))?,
                actor_id: relation
                    .to_ref
                    .as_actor_id()
                    .ok_or_else(|| corrupt("assignment target is not an Actor"))?
                    .clone(),
            });
    }
    let position_source = current_source_sql(
        "p",
        "jsonb_build_object('kind','strand_position','board_space_id',p.board_space_id,'strand_id',p.strand_id)",
    );
    let unproved_position = diesel::sql_query(format!(
            "SELECT EXISTS(SELECT 1 FROM strand_position_current_states p \
             WHERE p.realm_id=$1 AND NOT COALESCE(\
               {position_source}=jsonb_build_object('kind','realm','realm_id',p.realm_id),false)) AS present",
        )).bind::<Text,_>(realm_id.as_str()).get_result::<crate::ExistsRow>(&mut *conn).await?;
    if unproved_position.present {
        return Err(corrupt("position current has no covering RealmCommit").into());
    }
    let position_rows = diesel::sql_query(
        "SELECT board_space_id,strand_id,value FROM strand_position_current_states \
             WHERE realm_id=$1 ORDER BY strand_id,board_space_id",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<PositionRow>(&mut *conn)
    .await?;
    let mut positions: BTreeMap<StrandId, Vec<(SpaceId, StrandPositionCurrent)>> = BTreeMap::new();
    for row in position_rows {
        let board = row
            .board_space_id
            .parse::<SpaceId>()
            .map_err(|error| corrupt(error.to_string()))?;
        let strand = row
            .strand_id
            .parse::<StrandId>()
            .map_err(|error| corrupt(error.to_string()))?;
        let value = serde_json::from_value::<Option<StrandPositionCurrent>>(row.value)
            .map_err(PersistenceError::database)?;
        if let Some(value) = value {
            positions.entry(strand).or_default().push((board, value));
        }
    }
    let strand_rows = diesel::sql_query(
        "SELECT value FROM strand_current_states WHERE realm_id=$1 ORDER BY strand_id",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<ValueRow>(&mut *conn)
    .await?;
    let mut strands = Vec::new();
    for row in strand_rows {
        let strand: Strand =
            serde_json::from_value(row.value).map_err(PersistenceError::database)?;
        if strand.realm_id != *realm_id {
            return Err(corrupt("Strand Realm mismatch").into());
        }
        if !visible(strand.scope_circle_id.as_ref(), &circles) {
            continue;
        }
        let state = strand.state.ok_or_else(|| corrupt("Strand state absent"))?;
        if !include_terminal && state == ObjectState::Redacted {
            continue;
        }
        let id = strand.id.ok_or_else(|| corrupt("Strand id absent"))?;
        let mut placement = None;
        for (board_id, position) in positions.remove(&id).unwrap_or_default() {
            let board = space_objects
                .get(&board_id)
                .ok_or_else(|| corrupt("position Board metadata absent"))?;
            let list = space_objects
                .get(&position.list_space_id)
                .ok_or_else(|| corrupt("position List metadata absent"))?;
            if !visible(board.scope_circle_id.as_ref(), &circles)
                || !visible(list.scope_circle_id.as_ref(), &circles)
            {
                continue;
            }
            if board.kind != "board"
                || list.kind != "list"
                || strand.scope_circle_id != board.scope_circle_id
                || strand.scope_circle_id != list.scope_circle_id
            {
                return Err(
                    corrupt("position cannot form an available structural placement").into(),
                );
            }
            // Canonical position survives independently of target lifecycle.
            // A terminal target suppresses the derived edge, never the row.
            if board.state == Some(SpaceState::Tombstoned)
                || list.state == Some(SpaceState::Tombstoned)
            {
                continue;
            }
            if list.parent_space_id.as_ref() != Some(&board_id) {
                return Err(corrupt("position List is not a child of its Board").into());
            }
            if placement.is_some() {
                return Err(corrupt(
                    "Strand has multiple visible Board placements; this row cannot select one",
                )
                .into());
            }
            placement = Some((board_id, position));
        }
        let assigned = assignments.remove(&id).unwrap_or_default();
        let mut actors = assigned
            .iter()
            .map(|row| row.actor_id.clone())
            .collect::<Vec<_>>();
        actors.sort_by_key(ToString::to_string);
        actors.dedup();
        strands.push(StrandView {
            is_default: default.as_ref() == Some(&id),
            strand_id: id,
            realm_id: strand.realm_id,
            state,
            state_changed_at: strand.state_changed_at,
            stage: strand.stage,
            stage_changed_at: strand.stage_changed_at,
            title: strand
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.title.clone()),
            summary: strand
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.summary.clone()),
            topic: strand.topic,
            board_space_id: placement.as_ref().map(|(board, _)| board.clone()),
            list_space_id: placement
                .as_ref()
                .map(|(_, position)| position.list_space_id.clone()),
            rank: placement.map(|(_, position)| position.rank),
            assigned_actor_ids: actors,
            assigned_to_relations: assigned,
            created_by: Some(strand.created_by),
            created_at: Some(strand.created_at),
            updated_by: strand.updated_by,
            updated_at: strand.updated_at,
        });
    }
    Ok(Some((
        SpacePage {
            realm_id: realm_id.clone(),
            total_count: spaces.len() as u64,
            spaces,
            next_cursor: None,
            has_more: false,
        },
        StrandPage {
            realm_id: realm_id.clone(),
            total_count: strands.len() as u64,
            strands,
            next_cursor: None,
            has_more: false,
        },
    )))
}

/// Read public lists and every accepted current dependency at one database cut.
/// This internal carrier is never a second wire projection or hydration token.
pub(crate) async fn delivery_for_actor(
    pool: &PgPool,
    realm_id: &RealmId,
    actor: &ActorId,
    include_terminal: bool,
) -> PersistenceResult<
    Option<(
        SpacePage,
        StrandPage,
        arkret_models_collaboration::sync_frames::current_states::AccountStateView,
    )>,
> {
    let mut conn = pool.get().await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        let Some((spaces, strands)) =
            lists_for_actor_in_connection(conn, realm_id, actor, include_terminal).await?
        else {
            return Ok(None);
        };
        let material =
            crate::authority_commit::realm_state_snapshot_material_in_connection(conn, realm_id)
                .await?
                .ok_or_else(|| corrupt("projection lists have no current Realm authority"))?;
        spaces.validate().map_err(PersistenceError::database)?;
        strands.validate().map_err(PersistenceError::database)?;
        let entries = list_dependencies(&spaces, &strands, &material.current_state_entries)?;
        for row in &entries {
            let arkret_wire::CurrentState::Value {
                source_stream_ref,
                revision,
                ..
            } = row;
            let head = material
                .visible_stream_heads
                .iter()
                .find(|head| &head.stream_ref == source_stream_ref)
                .ok_or_else(|| corrupt("projection current has no accepted head"))?;
            if revision.stream_position > head.stream_position
                || (revision.stream_position == head.stream_position
                    && revision.commit_id != head.commit_id)
            {
                return Err(corrupt("projection current revision is outside its held head").into());
            }
        }
        let streams = entries
            .iter()
            .map(|row| {
                let arkret_wire::CurrentState::Value {
                    source_stream_ref, ..
                } = row;
                source_stream_ref.clone()
            })
            .collect::<BTreeSet<_>>();
        let stream_heads = material
            .visible_stream_heads
            .into_iter()
            .filter(|head| streams.contains(&head.stream_ref))
            .collect::<Vec<_>>();
        if streams
            .iter()
            .any(|stream| !stream_heads.iter().any(|head| &head.stream_ref == stream))
        {
            return Err(corrupt("projection dependency has no held stream head").into());
        }
        let view = arkret_models_collaboration::sync_frames::current_states::AccountStateView {
            realm_id: realm_id.clone(),
            governance_generation: material.governance_generation,
            stream_heads,
            entries,
        };
        view.validate().map_err(PersistenceError::database)?;
        Ok(Some((spaces, strands, view)))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// Exact output equality also proves empty/default/assignment/placement absence.
/// The controller may see additional rows, but must see every returned row fully.
pub(crate) async fn projection_lists_match_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    actor: &ActorId,
    include_terminal: bool,
    spaces: &SpacePage,
    strands: &StrandPage,
    owner: &arkret_wire::AccountId,
) -> PersistenceResult<bool> {
    let Some(current) = lists_for_actor_in_connection(conn, realm, actor, include_terminal)
        .await
        .map_err(PgTransactionError::into_persistence)?
    else {
        return Ok(false);
    };
    if canonical_pair(&current.0, &current.1)? != canonical_pair(spaces, strands)? {
        return Ok(false);
    }
    let Some((owner_spaces, owner_strands)) = lists_for_actor_in_connection(
        conn,
        realm,
        &ActorId::account(owner.clone()),
        include_terminal,
    )
    .await
    .map_err(PgTransactionError::into_persistence)?
    else {
        return Ok(false);
    };
    let owner_spaces = owner_spaces
        .spaces
        .iter()
        .map(arkret_canonical::canonical_json_bytes)
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(PersistenceError::database)?;
    for row in &spaces.spaces {
        if !owner_spaces.contains(
            &arkret_canonical::canonical_json_bytes(row).map_err(PersistenceError::database)?,
        ) {
            return Ok(false);
        }
    }
    for row in &strands.strands {
        let Some(owner_row) = owner_strands
            .strands
            .iter()
            .find(|owned| owned.strand_id == row.strand_id)
        else {
            return Ok(false);
        };
        // An owner may see additional assignment edges. That does not erase
        // permission to read the fully bound subset returned to this Agent.
        if row
            .assigned_to_relations
            .iter()
            .any(|edge| !owner_row.assigned_to_relations.contains(edge))
            || row
                .assigned_actor_ids
                .iter()
                .any(|actor| !owner_row.assigned_actor_ids.contains(actor))
        {
            return Ok(false);
        }
        let mut owner_row = owner_row.clone();
        owner_row.assigned_to_relations = row.assigned_to_relations.clone();
        owner_row.assigned_actor_ids = row.assigned_actor_ids.clone();
        if arkret_canonical::canonical_json_bytes(&owner_row).map_err(PersistenceError::database)?
            != arkret_canonical::canonical_json_bytes(row).map_err(PersistenceError::database)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn canonical_pair(spaces: &SpacePage, strands: &StrandPage) -> PersistenceResult<Vec<u8>> {
    arkret_canonical::canonical_json_bytes(&(spaces, strands)).map_err(PersistenceError::database)
}

/// Select original registered rows; no parent/placement field is synthesized as
/// a metadata value and no missing provenance is replaced by a cache snapshot.
fn list_dependencies(
    spaces: &SpacePage,
    strands: &StrandPage,
    rows: &[arkret_wire::CurrentState],
) -> PersistenceResult<Vec<arkret_wire::CurrentState>> {
    use arkret_wire::{CurrentSelector as Selector, CurrentState as Row};
    let mut space_ids = spaces
        .spaces
        .iter()
        .map(|row| row.space_id.clone())
        .collect::<BTreeSet<_>>();
    let strand_ids = strands
        .strands
        .iter()
        .map(|row| row.strand_id.clone())
        .collect::<BTreeSet<_>>();
    let relation_ids = strands
        .strands
        .iter()
        .flat_map(|row| &row.assigned_to_relations)
        .map(|row| row.relation_id.clone())
        .collect::<BTreeSet<_>>();
    for row in &strands.strands {
        space_ids.extend(row.board_space_id.iter().cloned());
        space_ids.extend(row.list_space_id.iter().cloned());
    }
    // All positions of returned Strands participate in selecting (or omitting)
    // the single visible placement. Their Board/List parents are dependencies.
    for row in rows {
        if let Row::Value {
            selector:
                Selector::StrandPosition {
                    board_space_id,
                    strand_id,
                },
            value,
            ..
        } = row
            && strand_ids.contains(strand_id)
        {
            space_ids.insert(board_space_id.clone());
            let position: Option<StrandPositionCurrent> =
                serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
            if let Some(position) = position {
                space_ids.insert(position.list_space_id);
            }
        }
    }
    // A disclosed parent locator does not grant ancestor metadata. Only
    // actual output and placement dependencies belong in this read carrier.
    let mut selected = Vec::new();
    let mut space_families = BTreeMap::<SpaceId, u8>::new();
    let mut proved_strands = BTreeSet::new();
    let mut proved_relations = BTreeSet::new();
    for row in rows {
        let Row::Value {
            selector,
            value,
            source_stream_ref,
            ..
        } = row;
        if source_stream_ref.realm_id() != &spaces.realm_id || spaces.realm_id != strands.realm_id {
            return Err(corrupt(
                "projection current source belongs to another Realm",
            ));
        }
        let keep = match selector {
            Selector::Space { space_id } if space_ids.contains(space_id) => {
                let space: Space =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                if space.id.as_ref() != Some(space_id)
                    || space.realm_id != spaces.realm_id
                    || space.parent_space_id.is_some()
                    || space.child_scope_policy.is_some()
                {
                    return Err(corrupt(
                        "projection Space dependency identity or family differs",
                    ));
                }
                *space_families.entry(space_id.clone()).or_default() |= 1;
                true
            }
            Selector::SpaceParent { space_id } if space_ids.contains(space_id) => {
                *space_families.entry(space_id.clone()).or_default() |= 2;
                true
            }
            Selector::SpaceChildScopePolicy { space_id } if space_ids.contains(space_id) => {
                let _: Option<arkret_models_collaboration::objects::space::ChildScopePolicy> =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                *space_families.entry(space_id.clone()).or_default() |= 4;
                true
            }
            Selector::Strand { strand_id } if strand_ids.contains(strand_id) => {
                let strand: Strand =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                if strand.id.as_ref() != Some(strand_id) || strand.realm_id != strands.realm_id {
                    return Err(corrupt("projection Strand dependency identity differs"));
                }
                proved_strands.insert(strand_id.clone());
                true
            }
            Selector::StrandPosition { strand_id, .. } => strand_ids.contains(strand_id),
            Selector::Relation {
                primary_conflict_domain,
            } => {
                let relation: Relation =
                    serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
                relation
                    .validate_current_for_domain(&spaces.realm_id, primary_conflict_domain)
                    .map_err(PersistenceError::database)?;
                if let Some(id) = &relation.id
                    && relation_ids.contains(id)
                {
                    proved_relations.insert(id.clone());
                    true
                } else {
                    false
                }
            }
            Selector::RealmSetDefaultStrand => !strand_ids.is_empty(),
            _ => false,
        };
        if keep {
            selected.push(row.clone());
        }
    }
    if space_ids
        .iter()
        .any(|id| space_families.get(id) != Some(&7))
        || proved_strands != strand_ids
        || proved_relations != relation_ids
    {
        return Err(corrupt(
            "projection output or structure is missing an accepted dependency",
        ));
    }
    Ok(selected)
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
            "SELECT value FROM strand_current_states WHERE realm_id=$1 AND strand_id=$2",
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
        if !crate::circle_current_states::effective_member_in_connection(conn, realm_id, &circle_id, actor).await? {
            return Ok(None);
        }
        let joined = diesel::sql_query(
            "SELECT EXISTS(SELECT 1 FROM circle_member_state_current_states m \
             JOIN circle_current_states c ON c.circle_id=m.circle_id AND c.realm_id=m.realm_id \
             WHERE m.realm_id=$1 AND m.circle_id=$2 AND m.member_id=$3 AND m.membership='join' \
               AND circle_member_parent_join_current(m.realm_id,m.member_id,m.value) \
               AND circle_current_row_proved(m.realm_id,jsonb_build_object('kind','circle_member_state','circle_id',m.circle_id,'member_actor_id',m.member_id::jsonb),m.source_stream_ref,m.current_commit_id,m.current_stream_position,m.value) \
               AND circle_current_row_proved(c.realm_id,jsonb_build_object('kind','circle','circle_id',c.circle_id),c.source_stream_ref,c.current_commit_id,c.current_stream_position,c.value) \
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

use horme::OptionalExtension as _;

#[cfg(test)]
mod tests {
    use arkret_wire::{
        CommitStreamHead, CurrentRevision, CurrentSelector, CurrentState, RealmCommitId,
    };
    use diesel::sql_types::{BigInt, Timestamptz};

    use super::*;

    #[test]
    fn projection_dependencies_require_complete_parent_families() {
        let realm = RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap();
        let space_id = SpaceId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [11; 32],
        ));
        let parent_id = SpaceId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [12; 32],
        ));
        let actor = ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:watcher.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let space = Space::new(
            space_id.clone(),
            realm.clone(),
            "list",
            "accepted",
            actor.clone(),
        );
        let output = SpacePage {
            realm_id: realm.clone(),
            total_count: 1,
            next_cursor: None,
            has_more: false,
            spaces: vec![SpaceView {
                space_id: space_id.clone(),
                realm_id: realm.clone(),
                kind: space.kind.clone(),
                title: space.title.clone(),
                encrypted_metadata: None,
                parent_space_id: None,
                rank: None,
                state: SpaceState::Active,
                state_changed_at: None,
                created_by: Some(actor.clone()),
                created_at: Some(space.created_at),
                updated_at: None,
            }],
        };
        let strands = StrandPage {
            realm_id: realm.clone(),
            strands: vec![],
            total_count: 0,
            next_cursor: None,
            has_more: false,
        };
        let make = |selector, value| CurrentState::Value {
            selector,
            value,
            source_stream_ref: CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            revision: CurrentRevision {
                commit_id: RealmCommitId::from_digest([13; 32]),
                stream_position: 3,
            },
        };
        let mut rows = vec![
            make(
                CurrentSelector::Space {
                    space_id: space_id.clone(),
                },
                serde_json::to_value(space).unwrap(),
            ),
            make(
                CurrentSelector::SpaceParent {
                    space_id: space_id.clone(),
                },
                serde_json::json!({"parent_space_id":null}),
            ),
            make(
                CurrentSelector::SpaceChildScopePolicy {
                    space_id: space_id.clone(),
                },
                Value::Null,
            ),
        ];
        assert_eq!(
            list_dependencies(&output, &strands, &rows).unwrap().len(),
            3
        );
        assert!(
            list_dependencies(&output, &strands, &rows[..2]).is_err(),
            "metadata and parent alone cannot replace a missing policy family"
        );
        let CurrentState::Value { value, .. } = &mut rows[1];
        *value = serde_json::json!({"parent_space_id":parent_id});
        let mut parent_output = output.clone();
        parent_output.spaces[0].parent_space_id = Some(parent_id);
        assert_eq!(
            list_dependencies(&parent_output, &strands, &rows)
                .unwrap()
                .len(),
            3,
            "a disclosed parent locator never requires an ancestor metadata read"
        );
    }

    #[tokio::test]
    async fn projection_delivery_rechecks_output_absence_fields_and_owner_membership() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let realm = RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap();
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let owner = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:owner.example").unwrap(),
            station.clone(),
        );
        let actor = ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:reader.example").unwrap(),
            station,
        ));
        let owner_actor = ActorId::account(owner.clone());
        let source = CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let source_json = serde_json::to_value(&source).unwrap();
        let commit = RealmCommitId::from_digest([25; 32]);
        let key = crate::authority_commit::stream_key(&source).unwrap();
        let now = chrono::Utc::now();
        let mut conn = pool.get().await.unwrap();
        // Imported accepted-history fixture exercises the durable reader cut,
        // not producer signatures or full HTTP admission.
        diesel::sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,governance_generation,commit_json,committed_at) VALUES($1,$2,$3,$4,0,0,$5,$6)")
            .bind::<Text,_>(commit.as_str()).bind::<Text,_>(realm.as_str())
            .bind::<Text,_>(&key).bind::<Jsonb,_>(&source_json)
            .bind::<Jsonb,_>(serde_json::json!({"stream_ref":source_json}))
            .bind::<Timestamptz,_>(now).execute(&mut *conn).await.unwrap();
        for member in [&actor, &owner_actor] {
            diesel::sql_query("INSERT INTO member_state_current_states(realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,'join',$3,0,$4,$5)")
                .bind::<Text,_>(realm.as_str()).bind::<Text,_>(member.to_string())
                .bind::<Text,_>(commit.as_str()).bind::<Jsonb,_>(serde_json::json!({"membership":"join"}))
                .bind::<Timestamptz,_>(now).execute(&mut *conn).await.unwrap();
        }
        let (empty_spaces, empty_strands) =
            lists_for_actor_in_connection(&mut conn, &realm, &actor, false)
                .await
                .map_err(PgTransactionError::into_persistence)
                .unwrap()
                .unwrap();
        assert!(
            projection_lists_match_in_connection(
                &mut conn,
                &realm,
                &actor,
                false,
                &empty_spaces,
                &empty_strands,
                &owner
            )
            .await
            .unwrap()
        );
        let space_id = SpaceId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [26; 32],
        ));
        let space = Space::new(
            space_id.clone(),
            realm.clone(),
            "list",
            "accepted title",
            actor.clone(),
        );
        let space_value = serde_json::to_value(&space).unwrap();
        diesel::sql_query("INSERT INTO space_current_states(realm_id,space_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,0,$4,$5)")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(space_id.as_str()).bind::<Text,_>(commit.as_str())
            .bind::<Jsonb,_>(&space_value).bind::<Timestamptz,_>(now).execute(&mut *conn).await.unwrap();
        diesel::sql_query("INSERT INTO space_parent_current_states(realm_id,space_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,0,$4,$5)")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(space_id.as_str()).bind::<Text,_>(commit.as_str())
            .bind::<Jsonb,_>(serde_json::json!({"parent_space_id":null})).bind::<Timestamptz,_>(now).execute(&mut *conn).await.unwrap();
        diesel::sql_query("INSERT INTO space_child_scope_policy_current_states(realm_id,space_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,0,'null'::jsonb,$4)")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(space_id.as_str()).bind::<Text,_>(commit.as_str())
            .bind::<Timestamptz,_>(now).execute(&mut *conn).await.unwrap();
        assert!(
            !projection_lists_match_in_connection(
                &mut conn,
                &realm,
                &actor,
                false,
                &empty_spaces,
                &empty_strands,
                &owner
            )
            .await
            .unwrap(),
            "a previously empty list is not a current negative fact after insertion"
        );
        let (spaces, strands) = lists_for_actor_in_connection(&mut conn, &realm, &actor, false)
            .await
            .map_err(PgTransactionError::into_persistence)
            .unwrap()
            .unwrap();
        assert!(
            projection_lists_match_in_connection(
                &mut conn, &realm, &actor, false, &spaces, &strands, &owner
            )
            .await
            .unwrap()
        );
        let mut forged = spaces.clone();
        forged.total_count += 1;
        assert!(
            !projection_lists_match_in_connection(
                &mut conn, &realm, &actor, false, &forged, &strands, &owner
            )
            .await
            .unwrap(),
            "total is part of exact output"
        );
        diesel::sql_query("UPDATE space_current_states SET value=jsonb_set(value,'{title}','\"updated title\"'::jsonb) WHERE space_id=$1")
            .bind::<Text,_>(space_id.as_str()).execute(&mut *conn).await.unwrap();
        assert!(
            !projection_lists_match_in_connection(
                &mut conn, &realm, &actor, false, &spaces, &strands, &owner
            )
            .await
            .unwrap(),
            "same selector and Commit cannot replace exact returned field bytes"
        );
        let (spaces, strands) = lists_for_actor_in_connection(&mut conn, &realm, &actor, false)
            .await
            .map_err(PgTransactionError::into_persistence)
            .unwrap()
            .unwrap();
        assert!(
            projection_lists_match_in_connection(
                &mut conn, &realm, &actor, false, &spaces, &strands, &owner
            )
            .await
            .unwrap()
        );
        diesel::sql_query("UPDATE member_state_current_states SET membership='leave',value=jsonb_build_object('membership','leave') WHERE realm_id=$1 AND member_id=$2")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(owner_actor.to_string()).execute(&mut *conn).await.unwrap();
        assert!(
            !projection_lists_match_in_connection(
                &mut conn, &realm, &actor, false, &spaces, &strands, &owner
            )
            .await
            .unwrap(),
            "recipient membership cannot substitute the controller's current readable scope"
        );
    }

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
        diesel::sql_query("INSERT INTO strand_current_states(realm_id,strand_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6)")
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
        let entry = CurrentState::Value {
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

        diesel::sql_query("UPDATE strand_current_states SET value=jsonb_set(value,'{metadata,title}','\"forged\"') WHERE strand_id=$1")
            .bind::<Text,_>(id.as_str()).execute(&mut *conn).await.unwrap();
        assert!(
            store.snapshot().await.is_err(),
            "verified evidence cannot cover another value"
        );
        diesel::sql_query("UPDATE strand_current_states SET value=$2 WHERE strand_id=$1")
            .bind::<Text, _>(id.as_str())
            .bind::<Jsonb, _>(&value)
            .execute(&mut *conn)
            .await
            .unwrap();
        // Corrupt the endpoint without violating the interval shape constraint.
        diesel::sql_query(
            "UPDATE replica_authorization_cuts SET head_commit_id=$2,circle_effect_base_commit_id=$2 WHERE realm_id=$1",
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
        diesel::sql_query("UPDATE replica_authorization_cuts SET head_commit_id=$2,head_stream_position=2,circle_effect_base_commit_id=$2,circle_effect_base_stream_position=2 WHERE realm_id=$1")
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
            "SELECT EXISTS(SELECT 1 FROM strand_current_states s WHERE s.realm_id=$1 AND {live} IS NOT NULL) AS present"
        )).bind::<Text,_>(realm.as_str()).get_result(&mut *conn).await.unwrap();
        assert!(
            !live_read.present,
            "historical cache evidence cannot restore a live cut"
        );

        diesel::sql_query("UPDATE strand_current_states SET value=jsonb_set(value,'{metadata,title}','\"forged\"') WHERE strand_id=$1")
            .bind::<Text,_>(id.as_str()).execute(&mut *conn).await.unwrap();
        assert!(
            store.snapshot().await.is_err(),
            "an anchor cannot cover another value"
        );
        diesel::sql_query("UPDATE strand_current_states SET value=$2 WHERE strand_id=$1")
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

#[derive(diesel::QueryableByName)]
struct RealmLinkCurrentRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    target_realm_id: String,
    #[diesel(sql_type = Text)]
    link_kind: String,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    envelope: Option<Value>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    commit_json: Option<Value>,
}

/// Registered link lists consume the durable latest row and its original
/// accepted Event/Commit. Missing provenance is unavailable, never an empty list.
pub(crate) async fn realm_link_list_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    realm: &RealmId,
    actor: &ActorId,
    station: &arkret_wire::DidCoreId,
    direction: arkret_models_collaboration::governance::realm_governance::RealmLinkDirection,
    allow: Option<&[String]>,
) -> PersistenceResult<
    Option<(
        arkret_models_collaboration::governance::realm_governance::RealmLinkList,
        Vec<arkret_wire::CommittedEventFullView>,
    )>,
> {
    use arkret_models_collaboration::governance::realm_governance::{
        RealmLinkDirection, RealmLinkList, RealmLinkPayload, RealmLinkView,
    };
    if !crate::authority_commit::accepted_realm_reader_in_connection(conn, realm, actor).await? {
        return Ok(None);
    }
    crate::realm_authorization_cut::RealmAuthorizationCut::read_accepted(conn, realm, actor)
        .await?
        .require_realm_projection_read(chrono::Utc::now())?;
    let rows = diesel::sql_query(
        "SELECT l.realm_id,l.target_realm_id,l.link_kind,l.status,l.value,e.envelope,c.commit_json \
         FROM realm_link_current_states l \
         LEFT JOIN realm_commits c ON c.realm_id=l.realm_id AND c.commit_id=l.current_commit_id \
           AND c.stream_position=l.current_stream_position \
           AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',l.realm_id) \
         LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
         WHERE (($2 IN ('outbound','both') AND l.realm_id=$1) \
            OR ($2 IN ('inbound','both') AND l.target_realm_id=$1)) \
         ORDER BY l.target_realm_id,l.link_kind,l.realm_id",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(match direction {
        RealmLinkDirection::Outbound => "outbound",
        RealmLinkDirection::Inbound => "inbound",
        RealmLinkDirection::Both => "both",
    })
    .load::<RealmLinkCurrentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut result = Vec::new();
    let mut sources = Vec::new();
    for row in rows {
        if allow.is_some_and(|allow| !allow.contains(&row.link_kind)) {
            continue;
        }
        let source_realm =
            RealmId::new(row.realm_id.clone()).map_err(PersistenceError::database)?;
        if !crate::authority_commit::accepted_realm_reader_in_connection(conn, &source_realm, actor)
            .await?
        {
            continue;
        }
        let corrupt = || {
            PersistenceError::Internal("Realm link current has no exact accepted original".into())
        };
        let event: arkret_wire::Event =
            serde_json::from_value(row.envelope.ok_or_else(corrupt)?).map_err(|_| corrupt())?;
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(row.commit_json.ok_or_else(corrupt)?).map_err(|_| corrupt())?;
        let value: RealmLinkPayload =
            serde_json::from_value(row.value.clone()).map_err(|_| corrupt())?;
        if event.kind != arkret_wire::EventKind::RealmLink
            || event.realm_id.as_str() != row.realm_id
            || commit.event_ref != event.event_id
            || commit.realm_id != event.realm_id
            || serde_json::to_value(&event.payload).map_err(PersistenceError::database)?
                != row.value
            || value.target_realm_id.as_str() != row.target_realm_id
            || value.link_kind.as_str() != row.link_kind
            || value.status.as_str() != row.status
        {
            return Err(corrupt());
        }
        event
            .verify_event_id_matches_content_with_digest_suite(
                event.event_id.digest_suite_code().digest_suite(),
            )
            .map_err(|_| corrupt())?;
        commit
            .verify_commit_id_matches_content()
            .map_err(|_| corrupt())?;
        let full = arkret_wire::CommittedEventFullView {
            event: event.clone(),
            commit: commit.clone(),
        };
        let disclosed =
            crate::committed_disclosure::disclose_in_connection(conn, vec![full.clone()]).await?;
        #[derive(diesel::QueryableByName)]
        struct Governor {
            #[diesel(sql_type=Text)]
            service_id: String,
        }
        let governor =
            diesel::sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
                .bind::<Text, _>(source_realm.as_str())
                .get_result::<Governor>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
        let governs = governor.service_id == station.as_str();
        let floor = crate::account_content_delivery::export_floor_in_connection(
            conn,
            &full.commit.stream_ref,
            actor,
            governs,
        )
        .await?;
        if floor.is_none_or(|floor| full.commit.stream_position < floor)
            || !matches!(
                disclosed.as_slice(),
                [arkret_wire::CommittedEventView::Full(_)]
            )
            || !crate::committed_disclosure::full_event_for_member_in_connection(
                conn,
                &full,
                actor,
                chrono::Utc::now(),
            )
            .await?
        {
            continue;
        }
        sources.push(full);
        result.push(RealmLinkView {
            realm_id: event.realm_id,
            target_realm_id: value.target_realm_id,
            link_kind: value.link_kind,
            status: value.status,
            label: value.label,
            commitment: value.commitment,
            created_at: event.created_at,
            updated_at: std::cmp::max(event.created_at, commit.committed_at),
        });
    }
    Ok(Some((
        RealmLinkList {
            realm_id: realm.clone(),
            direction,
            links: result,
        },
        sources,
    )))
}

/// Organization visibility and its accepted statements use one read cut.
/// Display-only declarations remain separate from verified relationships.
pub(crate) async fn realm_organization_read(
    pool: &PgPool,
    realm: &RealmId,
    caller: &ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<arkret_models_collaboration::governance::realm_governance::RealmOrganizationRelationshipList>>{
    use arkret_models_collaboration::governance::realm_governance::{
        RealmOrganizationLifecyclePhase, RealmOrganizationRelationshipList,
    };
    #[derive(diesel::QueryableByName)]
    struct DeclaredRow {
        #[diesel(sql_type=Text)]
        organization_id: arkret_wire::DidCoreId,
    }
    let mut conn = pool.get().await.map_err(PersistenceError::database)?;
    conn.transaction::<_,PgTransactionError,_>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ").execute(&mut *conn).await?;
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn,realm).await?;
        if !crate::authority_commit::accepted_current_member_joined_in_connection(conn,realm,caller).await? { return Ok(None); }
        let relationships=crate::organization_moderation_gate::accepted_relationships_in_connection(conn,realm,at).await?;
        let verified:BTreeSet<_>=relationships.iter().filter(|row|row.lifecycle_phase==RealmOrganizationLifecyclePhase::VerifiedActive).map(|row|row.organization_id.clone()).collect();
        let declared=diesel::sql_query("SELECT organization_id FROM realm_owning_organizations WHERE realm_id=$1 ORDER BY organization_id")
            .bind::<Text,_>(realm.as_str()).load::<DeclaredRow>(&mut *conn).await?;
        Ok(Some(RealmOrganizationRelationshipList { realm_id:realm.clone(), relationships,
            declared_organization_hint_ids:declared.into_iter().map(|row|row.organization_id).filter(|id|!verified.contains(id)).collect() }))
    }).await.map_err(PgTransactionError::into_persistence)
}
