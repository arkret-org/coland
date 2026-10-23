//! Native Morph read material from immutable accepted originals, never mirror caches.
//! Internal originals are reducer inputs, not an Event-history disclosure grant.
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use arkret_event_draft::ProjectedEventOperation;
use arkret_models_collaboration::objects::query_projection::{
    DocumentMorphProjectionOutcome, ProjectionMorphList,
};
use arkret_wire::{
    ActorId, CommitStreamHead, CommitStreamRef, CommittedEventFullView, DidCoreId, EventKind,
    RealmId,
};
use coland_storage::{
    CommitStreamProjection, PersistenceError, PersistenceResult, ProjectionState, ServerHlc,
};
use diesel::sql_types::{BigInt, Bool, Jsonb, Nullable, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "revision_unavailable: native Morph projection: {detail}"
    ))
}

#[derive(QueryableByName)]
struct Governor {
    #[diesel(sql_type = Text)]
    service_id: String,
}

#[derive(QueryableByName)]
struct SourceRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
    #[diesel(sql_type = Text)]
    stream_key: String,
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    envelope: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Text>)]
    operation_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    event_kind: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    operation_kind: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    sender: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    realm_id: Option<String>,
    #[diesel(sql_type = Nullable<Jsonb>)]
    payload: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(QueryableByName)]
struct HeldHeadRow {
    #[diesel(sql_type = Jsonb)]
    stream_ref: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
    #[diesel(sql_type = Text)]
    commit_id: String,
}
#[derive(QueryableByName)]
struct CurrentSourceRow {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Nullable<Jsonb>)]
    source_stream_ref: Option<serde_json::Value>,
}
#[derive(QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

/// Use the same governing source/head and registered current ports as the
/// production snapshot. A valid prefix alone cannot prove an empty result.
async fn require_complete_held_sources(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    streams: &CommitStreamProjection,
    originals: &BTreeMap<arkret_wire::EventId, CommittedEventFullView>,
) -> PersistenceResult<()> {
    let rows = sql_query(crate::authority_commit::REALM_STREAM_HEADS_SQL)
        .bind::<Text, _>(realm.as_str())
        .load::<HeldHeadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let mut held = BTreeMap::new();
    for row in rows {
        let head = CommitStreamHead {
            stream_ref: serde_json::from_value(row.stream_ref).map_err(unavailable)?,
            stream_position: u64::try_from(row.stream_position).map_err(unavailable)?,
            commit_id: row.commit_id.parse().map_err(unavailable)?,
        };
        if head.stream_ref.realm_id() != realm
            || held.insert(head.stream_ref.clone(), head).is_some()
        {
            return Err(unavailable("governing head set is malformed"));
        }
    }
    if &held != streams.stream_heads() {
        return Err(unavailable(
            "reconstructed streams do not cover the held governing head set",
        ));
    }
    let query = format!(
        "SELECT current_commit_id,current_stream_position,source_stream_ref FROM ({}) native_current",
        crate::authority_commit::SNAPSHOT_CURRENT_SQL
    );
    let current = sql_query(query)
        .bind::<Text, _>(realm.as_str())
        .load::<CurrentSourceRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let commits = originals
        .values()
        .map(|full| (&full.commit.commit_id, &full.commit))
        .collect::<BTreeMap<_, _>>();
    for row in current {
        let id: arkret_wire::RealmCommitId = row.current_commit_id.parse().map_err(unavailable)?;
        let commit = commits.get(&id).ok_or_else(|| {
            unavailable("registered current source is outside the complete accepted cut")
        })?;
        let stream: CommitStreamRef = serde_json::from_value(
            row.source_stream_ref
                .ok_or_else(|| unavailable("registered current source has no covering Commit"))?,
        )
        .map_err(unavailable)?;
        if commit.stream_ref != stream
            || commit.stream_position
                != u64::try_from(row.current_stream_position).map_err(unavailable)?
        {
            return Err(unavailable(
                "registered current source coordinates differ from its accepted Commit",
            ));
        }
    }
    // Accepted bodies and retained Commits are atomic immutable sources. A
    // missing final Commit must not make a body disappear from reconstruction.
    let orphan = sql_query("SELECT EXISTS(SELECT 1 FROM committed_events e WHERE e.realm_id=$1 AND NOT EXISTS(SELECT 1 FROM realm_commits c WHERE c.event_pk=e.pk AND c.realm_id=e.realm_id)) AS present")
        .bind::<Text, _>(realm.as_str()).get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if orphan.present {
        return Err(unavailable(
            "accepted Realm original has no retained covering Commit",
        ));
    }
    Ok(())
}

/// Process-local reconstruction only. No serialization or client-supplied basis.
struct NativeMaterial {
    state: ProjectionState,
    originals: BTreeMap<arkret_wire::EventId, CommittedEventFullView>,
    heads: Vec<CommitStreamHead>,
}

fn operation_from_original(
    row: &SourceRow,
    full: &CommittedEventFullView,
) -> PersistenceResult<Option<ProjectedEventOperation>> {
    let event = &full.event;
    if row.event_kind.is_none() {
        if event.kind.is_reducer_input() {
            return Err(unavailable(
                "accepted reducer Event has no original operation mapping",
            ));
        }
        return Ok(None);
    }
    if row.event_kind.as_deref() != Some(event.kind.as_str())
        || row.sender.as_deref() != Some(event.actor_id.to_string().as_str())
        || row.realm_id.as_deref() != Some(event.realm_id.as_str())
        || row.payload.as_ref() != Some(&serde_json::to_value(&event.payload).map_err(unavailable)?)
        || row.created_at != Some(event.created_at)
    {
        return Err(unavailable(
            "operation mapping differs from accepted producer content",
        ));
    }
    let operation_id = row
        .operation_id
        .as_deref()
        .ok_or_else(|| unavailable("accepted operation mapping has no original OperationId"))?;
    let id = arkret_wire::OperationId::new(crate::ids::format_typed_uuid(
        "operation",
        &uuid::Uuid::parse_str(operation_id).map_err(unavailable)?,
    ))
    .map_err(unavailable)?;
    let kind = serde_json::from_value(serde_json::Value::String(
        row.operation_kind
            .clone()
            .ok_or_else(|| unavailable("original operation kind is missing"))?,
    ))
    .map_err(unavailable)?;
    let suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(unavailable)?;
    let operation = ProjectedEventOperation::from_accepted_event(id, kind, None, event, suite)
        .map_err(unavailable)?
        .with_committed_ref(arkret_wire::CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: full.commit.commit_id.clone(),
            stream_ref: full.commit.stream_ref.clone(),
            stream_position: full.commit.stream_position,
        })
        .map_err(unavailable)?;
    Ok(Some(operation))
}

async fn material_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    station: &DidCoreId,
) -> PersistenceResult<NativeMaterial> {
    let governor = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .get_result::<Governor>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| unavailable("current authority is missing"))?;
    if governor.service_id != station.as_str() {
        return Err(unavailable(
            "replica has no authenticated governing serial barrier",
        ));
    }
    let rows = sql_query(
        "SELECT c.commit_json,c.stream_position,c.stream_key,c.commit_id,e.envelope,\
        p.operation_id::text AS operation_id,p.event_kind,p.operation_kind,p.sender_id AS sender,\
        p.realm_id,p.payload,p.created_at \
        FROM realm_commits c LEFT JOIN committed_events e ON e.pk=c.event_pk \
        LEFT JOIN projection_events p ON p.event_pk=e.pk WHERE c.realm_id=$1 \
        ORDER BY c.stream_key COLLATE \"C\",c.stream_position,c.commit_id COLLATE \"C\"",
    )
    .bind::<Text, _>(realm.as_str())
    .load::<SourceRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut streams = CommitStreamProjection::new();
    let mut operations = BTreeMap::<CommitStreamRef, Vec<ProjectedEventOperation>>::new();
    let mut originals = BTreeMap::new();
    for row in rows {
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(row.commit_json.clone()).map_err(unavailable)?;
        if &commit.realm_id != realm
            || commit.stream_ref.realm_id() != realm
            || commit.commit_id.as_str() != row.commit_id
            || i64::try_from(commit.stream_position).map_err(unavailable)? != row.stream_position
            || crate::authority_commit::stream_key(&commit.stream_ref)? != row.stream_key
        {
            return Err(unavailable(
                "Commit coordinates differ from their original row",
            ));
        }
        let event: arkret_wire::Event = serde_json::from_value(
            row.envelope
                .clone()
                .ok_or_else(|| unavailable("accepted original is missing or withheld locally"))?,
        )
        .map_err(unavailable)?;
        let full =
            crate::committed_disclosure::accepted_full_event_in_connection(conn, &commit.event_ref)
                .await?
                .ok_or_else(|| unavailable("exact accepted producer/Commit pair is missing"))?;
        if full.event != event || full.commit != commit {
            return Err(unavailable("original differs from its accepted source"));
        }
        // This validator checks position zero, each predecessor and each independent head.
        streams.apply_committed(full.clone()).map_err(unavailable)?;
        if let Some(operation) = operation_from_original(&row, &full)? {
            operations
                .entry(commit.stream_ref.clone())
                .or_default()
                .push(operation);
        }
        if originals.insert(event.event_id.clone(), full).is_some() {
            return Err(unavailable(
                "one producer identity occurs in multiple accepted slots",
            ));
        }
    }
    if streams.stream_heads().is_empty() {
        return Err(unavailable(
            "complete accepted Realm opening is unavailable",
        ));
    }
    require_complete_held_sources(conn, realm, &streams, &originals).await?;
    let state = reduce_streams(operations, &originals, station)?;
    let heads = streams.stream_heads().values().cloned().collect();
    Ok(NativeMaterial {
        state,
        originals,
        heads,
    })
}

/// A typed local object reference carries its creating Event token. This is
/// the protocol's object derivation, never an invented OperationId mapping.
fn creating_event(reference: &str) -> Option<arkret_wire::EventId> {
    if let Ok(id) = reference.parse() {
        return Some(id);
    }
    for prefix in [
        "ak:circle:",
        "ak:morph:",
        "ak:strand:",
        "ak:space:",
        "ak:relation:",
    ] {
        if let Some(token) = reference.strip_prefix(prefix) {
            return format!("ak:event:{token}").parse().ok();
        }
    }
    None
}

fn dependencies(
    operation: &ProjectedEventOperation,
    originals: &BTreeMap<arkret_wire::EventId, CommittedEventFullView>,
) -> PersistenceResult<BTreeSet<arkret_wire::EventId>> {
    let mut dependencies = BTreeSet::new();
    for reference in operation
        .semantic_refs
        .iter()
        .filter(|reference| reference.critical)
    {
        if let Some(id) = creating_event(&reference.id) {
            if !originals.contains_key(&id) {
                return Err(unavailable(
                    "critical local source is not in the complete accepted cut",
                ));
            }
            dependencies.insert(id);
        }
    }
    if let arkret_wire::ScopeRef::Circle { circle_id, .. } = &operation.context.accepted_scope_ref {
        dependencies.insert(
            creating_event(circle_id.as_str())
                .ok_or_else(|| unavailable("Circle scope has no original creation token"))?,
        );
    }
    if let Some(circle) = operation
        .payload
        .get("object")
        .and_then(|object| object.get("scope_circle_id"))
        .and_then(serde_json::Value::as_str)
    {
        dependencies.insert(
            creating_event(circle)
                .ok_or_else(|| unavailable("Morph Circle fact has no original creation token"))?,
        );
    }
    if let Some(target) = operation
        .payload
        .get("target_ref")
        .or_else(|| operation.payload.get("object_ref"))
        .and_then(serde_json::Value::as_str)
        && target.starts_with("ak:morph:")
    {
        dependencies.insert(
            creating_event(target)
                .ok_or_else(|| unavailable("Morph target has no original creation token"))?,
        );
    }
    if dependencies.iter().any(|id| !originals.contains_key(id)) {
        return Err(unavailable(
            "object source is missing from the complete accepted cut",
        ));
    }
    Ok(dependencies)
}

fn reduce_streams(
    operations: BTreeMap<CommitStreamRef, Vec<ProjectedEventOperation>>,
    originals: &BTreeMap<arkret_wire::EventId, CommittedEventFullView>,
    station: &DidCoreId,
) -> PersistenceResult<ProjectionState> {
    let mut pending: BTreeMap<_, VecDeque<_>> = operations
        .into_iter()
        .map(|(stream, operations)| (stream, operations.into()))
        .collect();
    let projected_ids = pending
        .values()
        .flat_map(|entries| entries.iter())
        .map(|operation| operation.context.event_id.clone())
        .collect::<BTreeSet<_>>();
    let mut applied = originals
        .keys()
        .filter(|id| !projected_ids.contains(*id))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut state = ProjectionState::new();
    let clock = ServerHlc::new(station.as_str());
    let mut morph_streams = BTreeMap::<String, CommitStreamRef>::new();
    // Only a stream's head can advance. Among independent heads, accepted
    // semantic/object references determine readiness; timestamps never order
    // competing writes. Cross-stream Morph mutation has no supported current
    // proof here and is unavailable, rather than introducing an admission ban.
    while pending.values().any(|entries| !entries.is_empty()) {
        let mut ready = None;
        for (stream, entries) in &pending {
            if let Some(operation) = entries.front()
                && dependencies(operation, originals)?.is_subset(&applied)
            {
                ready = Some(stream.clone());
                break;
            }
        }
        let stream = ready.ok_or_else(|| {
            unavailable("accepted source dependency cycle or missing predecessor")
        })?;
        let operation = pending
            .get_mut(&stream)
            .and_then(VecDeque::pop_front)
            .ok_or_else(|| unavailable("ready stream lost its original operation"))?;
        if operation.event_kind == EventKind::MorphCreate {
            let id = arkret_wire::MorphId::from_event_id(&operation.context.event_id).to_string();
            if morph_streams.insert(id, stream.clone()).is_some() {
                return Err(unavailable("Morph creation has multiple accepted sources"));
            }
        } else if let Some(target) = operation
            .payload
            .get("target_ref")
            .or_else(|| operation.payload.get("object_ref"))
            .and_then(serde_json::Value::as_str)
            && target.starts_with("ak:morph:")
            && morph_streams.get(target) != Some(&stream)
        {
            return Err(unavailable(
                "Morph current has no unique source-stream succession",
            ));
        }
        let relevant = operation.event_kind.as_str().starts_with("ak.morph.")
            || operation.event_kind == EventKind::CircleCreate
            || operation.event_kind == EventKind::RealmCreate
            || operation
                .payload
                .get("object_ref")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|target| target.starts_with("ak:morph:"));
        let effect = state.apply(&operation, &clock);
        if relevant && matches!(effect, coland_storage::ProjectionEffect::Rejected { .. }) {
            return Err(unavailable(
                "accepted Morph scaffold could not be reduced from complete originals",
            ));
        }
        applied.insert(operation.context.event_id.clone());
    }
    if state
        .pending_replay
        .values()
        .flatten()
        .any(|entry| entry.operation.event_kind.as_str().starts_with("ak.morph."))
    {
        return Err(unavailable(
            "accepted Morph has unresolved semantic sources",
        ));
    }
    Ok(state)
}

/// Actual observable facts retained for final-time qualification. An unknown
/// field, facet, label or encrypted plaintext never becomes an invented allow.
#[derive(Clone)]
pub(crate) struct NativeReadFact {
    pub action: arkret_wire::CapabilityActionId,
    pub target: arkret_wire::WireResourceSelector,
    pub facts: coland_storage::OperationFacts,
    pub circle: Option<arkret_wire::CircleId>,
}

fn field_paths(value: &serde_json::Value) -> Vec<String> {
    fn visit(value: &serde_json::Value, prefix: &str, paths: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::Object(values) if !values.is_empty() => {
                for (key, value) in values {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    visit(value, &path, paths);
                }
            }
            serde_json::Value::Array(values) if !values.is_empty() => {
                for value in values {
                    visit(value, prefix, paths);
                }
            }
            _ if !prefix.is_empty() => {
                paths.insert(prefix.to_owned());
            }
            _ => {}
        }
    }
    let mut paths = BTreeSet::new();
    visit(value, "", &mut paths);
    paths.into_iter().collect()
}

fn fact_for_morph(
    morph: &coland_storage::MorphProjection,
    value: &serde_json::Value,
) -> PersistenceResult<NativeReadFact> {
    let realm: RealmId = morph.realm_id.parse().map_err(unavailable)?;
    let mut target = arkret_wire::WireResourceSelector::realm(realm);
    target.kind = arkret_wire::ResourceSelectorKind::Morph;
    target.morph_id = Some(morph.morph_id.parse().map_err(unavailable)?);
    target.morph_kind = Some(morph.morph_kind.clone());
    let circle = morph
        .scope_circle_id
        .as_ref()
        .map(|value| value.parse())
        .transpose()
        .map_err(unavailable)?;
    target.circle_id = circle.clone();
    let facts = coland_storage::OperationFacts {
        object_kind: Some("morph".into()),
        morph_kind: Some(morph.morph_kind.clone()),
        circle_id: morph.scope_circle_id.clone(),
        target_created_at: Some(morph.created_at),
        target_owner: Some(serde_json::from_str(&morph.created_by).map_err(unavailable)?),
        read_fields: Some(field_paths(value)),
        ..Default::default()
    };
    Ok(NativeReadFact {
        target,
        facts,
        circle,
        action: arkret_wire::CapabilityActionId::MorphRead,
    })
}

fn realm_fact(realm: &RealmId, value: &serde_json::Value) -> NativeReadFact {
    NativeReadFact {
        action: arkret_wire::CapabilityActionId::MorphRead,
        target: arkret_wire::WireResourceSelector::realm(realm.clone()),
        facts: coland_storage::OperationFacts {
            read_fields: Some(field_paths(value)),
            ..Default::default()
        },
        circle: None,
    }
}

async fn require_fact(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    fact: &NativeReadFact,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<crate::realm_authorization_cut::RealmAuthorizationCut> {
    let realm = fact
        .target
        .realm_id
        .as_ref()
        .ok_or_else(|| unavailable("native target has no Realm"))?;
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, realm, actor).await?;
    let source =
        crate::realm_authorization_cut::owned_source_in_connection(conn, realm, actor, at, false)
            .await?;
    cut.require_native_projection_read(&fact.target, &fact.facts, fact.action, source, at)?;
    Ok(cut)
}

async fn visible(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    circle: Option<&str>,
    actor: &ActorId,
) -> PersistenceResult<bool> {
    let Some(circle) = circle else {
        return Ok(true);
    };
    let circle = circle.parse().map_err(unavailable)?;
    // Native floor evaluation includes the exact current parent join revision;
    // the reducer's historical Circle member set cannot substitute that cut.
    Ok(
        crate::account_stream_scan::caller_circle_floor_in_connection(conn, realm, &circle, actor)
            .await?
            .is_some(),
    )
}

fn morph_row(
    morph: &coland_storage::MorphProjection,
) -> PersistenceResult<arkret_models_collaboration::objects::query_projection::ProjectionMorphRow> {
    use coland_storage::ObjectLifecycleState;
    let row = arkret_models_collaboration::objects::query_projection::ProjectionMorphRow {
        morph_id: morph.morph_id.parse().map_err(unavailable)?,
        realm_id: morph.realm_id.parse().map_err(unavailable)?,
        morph_kind: morph.morph_kind.clone(),
        title: morph.title.clone(),
        state: match morph.state {
            ObjectLifecycleState::Active => arkret_wire::ObjectState::Active,
            ObjectLifecycleState::Archived => arkret_wire::ObjectState::Archived,
            ObjectLifecycleState::Redacted => arkret_wire::ObjectState::Redacted,
        },
        state_changed_at: morph.state_changed_at,
        stage: morph.stage.clone(),
        stage_changed_at: morph.stage_changed_at,
        created_by: Some(serde_json::from_str(&morph.created_by).map_err(unavailable)?),
        created_at: Some(morph.created_at),
        updated_at: morph.updated_at,
    };
    row.validate().map_err(unavailable)?;
    Ok(row)
}

pub(crate) async fn list_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    actor: &ActorId,
    station: &DidCoreId,
    include_terminal: bool,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<(ProjectionMorphList, Vec<NativeReadFact>)>> {
    if !crate::authority_commit::accepted_current_member_joined_in_connection(conn, realm, actor)
        .await?
    {
        return Ok(None);
    }
    let material = material_in_connection(conn, realm, station).await?;
    debug_assert!(!material.heads.is_empty());
    let mut rows = Vec::new();
    let mut facts = Vec::new();
    for morph in material.state.morphs.values() {
        if morph.realm_id != realm.as_str()
            || (!include_terminal && morph.state.is_terminal())
            || !visible(conn, realm, morph.scope_circle_id.as_deref(), actor).await?
        {
            continue;
        }
        let row = morph_row(morph)?;
        let fact = fact_for_morph(morph, &serde_json::to_value(&row).map_err(unavailable)?)?;
        // A complete current source can establish this row as hidden. A missing
        // source or malformed fact is never silently converted to absence.
        require_fact(conn, actor, &fact, at).await?;
        let mut metadata = fact.clone();
        metadata.action = arkret_wire::CapabilityActionId::ObjectReadMetadata;
        require_fact(conn, actor, &metadata, at).await?;
        rows.push(row);
        facts.extend([fact, metadata]);
    }
    rows.sort_by(|left, right| left.morph_id.cmp(&right.morph_id));
    let output = ProjectionMorphList {
        realm_id: realm.clone(),
        total: u64::try_from(rows.len()).map_err(unavailable)?,
        morphs: rows,
        next_cursor: None,
        has_more: false,
    };
    output.validate().map_err(unavailable)?;
    if output.morphs.is_empty() {
        let fact = realm_fact(realm, &serde_json::to_value(&output).map_err(unavailable)?);
        require_fact(conn, actor, &fact, at).await?;
        let mut metadata = fact.clone();
        metadata.action = arkret_wire::CapabilityActionId::ObjectReadMetadata;
        require_fact(conn, actor, &metadata, at).await?;
        facts.extend([fact, metadata]);
    }
    Ok(Some((output, facts)))
}

async fn history_visible(
    conn: &mut AsyncPgConnection,
    full: &CommittedEventFullView,
    actor: &ActorId,
) -> PersistenceResult<bool> {
    let floor = match &full.commit.stream_ref {
        CommitStreamRef::Realm { realm_id } => {
            crate::account_stream_scan::caller_realm_floor_in_connection(conn, realm_id, actor)
                .await?
        }
        CommitStreamRef::Circle {
            realm_id,
            circle_id,
        } => {
            crate::account_stream_scan::caller_circle_floor_in_connection(
                conn, realm_id, circle_id, actor,
            )
            .await?
        }
        _ => return Ok(false),
    };
    Ok(floor.is_some_and(|floor| full.commit.stream_position >= floor.oldest_position))
}

fn object_map(value: serde_json::Value) -> PersistenceResult<BTreeMap<String, serde_json::Value>> {
    value
        .as_object()
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .ok_or_else(|| unavailable("native document row is not an object"))
}

pub(crate) async fn document_absence_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    morph: &arkret_wire::MorphId,
    actor: &ActorId,
    station: &DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Vec<NativeReadFact>> {
    if !crate::authority_commit::accepted_current_member_joined_in_connection(conn, realm, actor)
        .await?
    {
        return Err(unavailable(
            "document absence has no active actor membership",
        ));
    }
    let material = material_in_connection(conn, realm, station).await?;
    if material.state.morphs.contains_key(morph.as_str()) {
        return Err(unavailable(
            "existing or hidden Morph is not an authenticated absence",
        ));
    }
    let read = realm_fact(realm, &serde_json::json!({"morph_id":morph,"absent":true}));
    let mut metadata = read.clone();
    metadata.action = arkret_wire::CapabilityActionId::ObjectReadMetadata;
    for fact in [&read, &metadata] {
        require_fact(conn, actor, fact, at).await?;
    }
    Ok(vec![read, metadata])
}

pub(crate) async fn document_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    morph_id: &arkret_wire::MorphId,
    actor: &ActorId,
    station: &DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<(DocumentMorphProjectionOutcome, Vec<NativeReadFact>)>> {
    if !crate::authority_commit::accepted_current_member_joined_in_connection(conn, realm, actor)
        .await?
    {
        return Ok(None);
    }
    let material = material_in_connection(conn, realm, station).await?;
    let Some(morph) = material.state.morphs.get(morph_id.as_str()) else {
        let fact = realm_fact(
            realm,
            &serde_json::json!({"morph_id":morph_id,"absent":true}),
        );
        require_fact(conn, actor, &fact, at).await?;
        return Ok(None);
    };
    if morph.realm_id != realm.as_str()
        || morph.morph_kind != "document"
        || !visible(conn, realm, morph.scope_circle_id.as_deref(), actor).await?
    {
        return Ok(None);
    }
    if morph.encrypted_content.is_some() {
        return Err(unavailable(
            "encrypted document plaintext is not an observable native current fact",
        ));
    }
    let body =
        coland_storage::morph_document_body(&morph.fields).unwrap_or(serde_json::Value::Null);
    let document =
        arkret_models_collaboration::objects::query_projection::DocumentMorphProjection {
            morph_id: morph_id.clone(),
            realm_id: realm.clone(),
            morph_kind: morph.morph_kind.clone(),
            title: morph.title.clone(),
            state: morph.state.as_str().to_owned(),
            state_changed_at: morph.state_changed_at,
            fields: morph.fields.clone(),
            body: body.clone(),
            schema_refs: morph.schema_refs.clone(),
            facets: morph.facets.keys().cloned().collect(),
            created_by: Some(
                serde_json::from_str::<ActorId>(&morph.created_by).map_err(unavailable)?,
            ),
            created_at: Some(morph.created_at),
            updated_by: morph
                .updated_by
                .as_deref()
                .map(serde_json::from_str::<ActorId>)
                .transpose()
                .map_err(unavailable)?,
            updated_at: morph.updated_at,
            extensions: BTreeMap::new(),
        };
    let mut version_facts = Vec::new();
    let mut versions = Vec::new();
    for version in &morph.versions {
        let id: arkret_wire::EventId = version.event_id.parse().map_err(unavailable)?;
        let source = material
            .originals
            .get(&id)
            .ok_or_else(|| unavailable("document version has no accepted original"))?;
        if !history_visible(conn, source, actor).await? {
            continue;
        }
        let value = serde_json::json!({"version_id":version.version_id,"event_id":version.event_id,"author":version.author,
            "created_at":arkret_canonical::format_timestamp_canonical(version.created_at),"body_digest":version.body_digest,"body":version.body});
        let mut history = fact_for_morph(morph, &value)?;
        history.action = arkret_wire::CapabilityActionId::ObjectReadHistory;
        require_fact(conn, actor, &history, at).await?;
        version_facts.push(history);
        versions.push(object_map(value)?);
    }
    // Relation and comment builders below resolve their own accepted targets;
    // no live ProjectionService or private plaintext cache participates.
    let (relations, mut extra_facts) =
        relations_for_document(conn, &material, morph, actor, at).await?;
    let (comments, comment_facts) =
        comments_for_document(conn, &material, morph, &body, actor, at).await?;
    extra_facts.extend(comment_facts);
    extra_facts.extend(version_facts);
    let output = DocumentMorphProjectionOutcome {
        document,
        versions,
        relations,
        comments,
        checkpoint: None,
    };
    let fact = fact_for_morph(morph, &serde_json::to_value(&output).map_err(unavailable)?)?;
    require_fact(conn, actor, &fact, at).await?;
    extra_facts.push(fact);
    let mut content = fact_for_morph(
        morph,
        &serde_json::json!({"body":output.document.body,"fields":output.document.fields}),
    )?;
    content.action = arkret_wire::CapabilityActionId::ObjectReadContent;
    require_fact(conn, actor, &content, at).await?;
    extra_facts.push(content);
    let mut metadata_value = serde_json::to_value(&output.document).map_err(unavailable)?;
    if let Some(object) = metadata_value.as_object_mut() {
        object.remove("body");
        object.remove("fields");
    }
    let mut metadata = fact_for_morph(morph, &metadata_value)?;
    metadata.action = arkret_wire::CapabilityActionId::ObjectReadMetadata;
    require_fact(conn, actor, &metadata, at).await?;
    extra_facts.push(metadata);
    Ok(Some((output, extra_facts)))
}

fn original_object_event<'a>(
    material: &'a NativeMaterial,
    object: &str,
    prefix: &str,
) -> PersistenceResult<&'a CommittedEventFullView> {
    let suffix = object
        .strip_prefix(prefix)
        .ok_or_else(|| unavailable("native object identity is malformed"))?;
    let id: arkret_wire::EventId = format!("ak:event:{suffix}").parse().map_err(unavailable)?;
    material
        .originals
        .get(&id)
        .ok_or_else(|| unavailable("native object has no exact accepted creation"))
}

fn reference_fact(
    source: &CommittedEventFullView,
    target: arkret_wire::WireResourceSelector,
    value: &serde_json::Value,
    object_kind: &str,
    circle: Option<String>,
) -> PersistenceResult<NativeReadFact> {
    let typed_circle = circle
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(unavailable)?;
    let (strand_id, track) = if source.event.kind == EventKind::MessageCreate {
        let payload: arkret_models_collaboration::events_payloads::message::MessageCreatePayload =
            serde_json::from_value(
                serde_json::to_value(&source.event.payload).map_err(unavailable)?,
            )
            .map_err(unavailable)?;
        (
            Some(payload.strand_id.to_string()),
            Some(payload.track_name),
        )
    } else {
        (None, None)
    };
    Ok(NativeReadFact {
        target,
        circle: typed_circle,
        action: arkret_wire::CapabilityActionId::MorphRead,
        facts: coland_storage::OperationFacts {
            strand_id,
            track,
            object_kind: Some(object_kind.into()),
            circle_id: circle,
            target_owner: Some(source.event.actor_id.clone()),
            target_created_at: Some(source.event.created_at),
            read_fields: Some(field_paths(value)),
            ..Default::default()
        },
    })
}

async fn relations_for_document(
    conn: &mut AsyncPgConnection,
    material: &NativeMaterial,
    morph: &coland_storage::MorphProjection,
    actor: &ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<(
    Vec<BTreeMap<String, serde_json::Value>>,
    Vec<NativeReadFact>,
)> {
    let realm: RealmId = morph.realm_id.parse().map_err(unavailable)?;
    let mut result = Vec::new();
    let mut facts = Vec::new();
    for relation in material.state.relations.values().filter(|row| {
        row.is_active()
            && row.realm_id == morph.realm_id
            && (row.from_object_ref() == Some(morph.morph_id.as_str())
                || row.to_object_ref() == Some(morph.morph_id.as_str()))
    }) {
        if !visible(conn, &realm, relation.scope_circle_id.as_deref(), actor).await? {
            continue;
        }
        let source = original_object_event(material, &relation.relation_id, "ak:relation:")?;
        if !history_visible(conn, source, actor).await? {
            continue;
        }
        let (target, direction) = if relation.from_object_ref() == Some(morph.morph_id.as_str()) {
            (relation.to_object_ref(), "outgoing")
        } else {
            (relation.from_object_ref(), "incoming")
        };
        // Only an exact native target from this governing cut can be accessible.
        // Unknown/cross-Realm objects stay Locked, with no endpoint/field leak.
        let accessible = match target {
            // Actor endpoints need accepted current identity evidence that this
            // projection cut does not provide; retain the authorized LazyLink.
            None => false,
            Some(target) if target == realm.as_str() => {
                let fact = realm_fact(&realm, &serde_json::json!({"realm_id":realm}));
                let mut metadata = fact.clone();
                metadata.action = arkret_wire::CapabilityActionId::ObjectReadMetadata;
                require_fact(conn, actor, &fact, at).await?;
                require_fact(conn, actor, &metadata, at).await?;
                facts.extend([fact, metadata]);
                true
            }
            Some(target) => match material.state.morphs.get(target) {
                Some(endpoint)
                    if !endpoint.state.is_terminal()
                        && visible(conn, &realm, endpoint.scope_circle_id.as_deref(), actor)
                            .await? =>
                {
                    let fact = fact_for_morph(
                        endpoint,
                        &serde_json::json!({"morph_id":endpoint.morph_id}),
                    )?;
                    let mut metadata = fact.clone();
                    metadata.action = arkret_wire::CapabilityActionId::ObjectReadMetadata;
                    if require_fact(conn, actor, &fact, at).await.is_ok()
                        && require_fact(conn, actor, &metadata, at).await.is_ok()
                    {
                        facts.extend([fact, metadata]);
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            },
        };
        let value = if accessible {
            serde_json::json!({
                "relation_id":relation.relation_id,"relation_kind":relation.relation_kind,
                "from":relation.from_ref,"to":relation.to_ref,"fields":relation.fields,"state":relation.state,
                "created_at":arkret_canonical::format_timestamp_canonical(relation.created_at),"updated_at":arkret_canonical::format_timestamp_canonical(relation.updated_at),
                "reference_projection":{"status":"accessible"},
            })
        } else {
            serde_json::json!({
                "relation_id":relation.relation_id,"relation_kind":relation.relation_kind,"anchor_ref":morph.morph_id,
                "direction":direction,"state":relation.state,"reference_projection":{"status":"locked"},"locked":true,
            })
        };
        let mut target = arkret_wire::WireResourceSelector::realm(realm.clone());
        target.kind = arkret_wire::ResourceSelectorKind::Relation;
        target.relation_id = Some(relation.relation_id.parse().map_err(unavailable)?);
        target.circle_id = relation
            .scope_circle_id
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(unavailable)?;
        let fact = reference_fact(
            source,
            target,
            &value,
            "relation",
            relation.scope_circle_id.clone(),
        )?;
        require_fact(conn, actor, &fact, at).await?;
        let mut metadata = fact.clone();
        metadata.action = arkret_wire::CapabilityActionId::ObjectReadMetadata;
        require_fact(conn, actor, &metadata, at).await?;
        facts.extend([fact.clone(), metadata]);
        if accessible && !relation.fields.is_empty() {
            let mut content = fact;
            content.action = arkret_wire::CapabilityActionId::ObjectReadContent;
            content.facts.read_fields =
                Some(field_paths(&serde_json::json!({"fields":relation.fields})));
            require_fact(conn, actor, &content, at).await?;
            facts.push(content);
        }
        result.push((
            relation.relation_kind.clone(),
            relation.relation_id.clone(),
            object_map(value)?,
        ));
    }
    result.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    Ok((result.into_iter().map(|(_, _, row)| row).collect(), facts))
}

fn body_text_len(body: &serde_json::Value) -> usize {
    if let Some(text) = body.as_str() {
        return text.chars().count();
    }
    if let Some(blocks) = body.get("blocks").and_then(serde_json::Value::as_array) {
        return blocks
            .iter()
            .filter_map(|block| {
                block
                    .get("content")
                    .or_else(|| block.get("text"))
                    .or_else(|| block.get("body"))
                    .and_then(serde_json::Value::as_str)
            })
            .map(|text| text.chars().count())
            .sum();
    }
    body.get("content")
        .or_else(|| body.get("text"))
        .or_else(|| body.get("body"))
        .and_then(serde_json::Value::as_str)
        .map(|text| text.chars().count())
        .unwrap_or(0)
}

async fn comments_for_document(
    conn: &mut AsyncPgConnection,
    material: &NativeMaterial,
    morph: &coland_storage::MorphProjection,
    body: &serde_json::Value,
    actor: &ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<(
    Vec<BTreeMap<String, serde_json::Value>>,
    Vec<NativeReadFact>,
)> {
    let realm: RealmId = morph.realm_id.parse().map_err(unavailable)?;
    let mut result = Vec::new();
    let mut facts = Vec::new();
    for message in material.state.messages.values().filter(|message| {
        message.realm_id == morph.realm_id
            && !material.state.redactions.contains(&message.event_id)
            && message.redacted_at.is_none()
    }) {
        let id: arkret_wire::EventId = message.event_id.parse().map_err(unavailable)?;
        let source = material
            .originals
            .get(&id)
            .ok_or_else(|| unavailable("comment source has no accepted original"))?;
        if !history_visible(conn, source, actor).await? {
            continue;
        }
        let circle = match &source.event.scope_ref {
            arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id.to_string()),
            arkret_wire::ScopeRef::Realm { realm_id } if realm_id == &realm => None,
            _ => return Err(unavailable("comment has no registered content scope")),
        };
        if !visible(conn, &realm, circle.as_deref(), actor).await? {
            continue;
        }
        if message.encrypted {
            return Err(unavailable(
                "encrypted Message cannot prove complete document comment absence",
            ));
        }
        let Some(anchor) = message.content.get("anchor_range").filter(|anchor| {
            anchor.get("target_ref").and_then(serde_json::Value::as_str)
                == Some(morph.morph_id.as_str())
        }) else {
            continue;
        };
        let Some(text) = message
            .content
            .get("body")
            .or_else(|| message.content.get("text"))
            .or_else(|| message.content.get("label"))
            .and_then(serde_json::Value::as_str)
            .filter(|text| !text.trim().is_empty())
        else {
            continue;
        };
        let state = if anchor
            .get("end")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|end| usize::try_from(end).map_or(true, |end| end > body_text_len(body)))
        {
            "orphaned"
        } else {
            "active"
        };
        let value = serde_json::json!({"event_id":message.event_id,"actor_id":source.event.actor_id,
            "created_at":arkret_canonical::format_timestamp_canonical(message.created_at),"body":text,"anchor_range":anchor,"state":state,"content":message.content});
        let mut target = arkret_wire::WireResourceSelector::realm(realm.clone());
        target.kind = arkret_wire::ResourceSelectorKind::Message;
        target.message_id = Some(message.message_id.parse().map_err(unavailable)?);
        target.circle_id = circle
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(unavailable)?;
        let fact = reference_fact(source, target, &value, "message", circle)?;
        require_fact(conn, actor, &fact, at).await?;
        let mut history = fact.clone();
        history.action = arkret_wire::CapabilityActionId::ObjectReadHistory;
        require_fact(conn, actor, &history, at).await?;
        let mut content = fact.clone();
        content.action = arkret_wire::CapabilityActionId::ObjectReadContent;
        require_fact(conn, actor, &content, at).await?;
        facts.extend([fact, history, content]);
        result.push((
            message.created_at,
            message.event_id.clone(),
            object_map(value)?,
        ));
    }
    result.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    Ok((result.into_iter().map(|(_, _, row)| row).collect(), facts))
}

pub(crate) async fn list_for_actor(
    pool: &crate::PgPool,
    realm: &RealmId,
    actor: &ActorId,
    station: &DidCoreId,
    include_terminal: bool,
) -> PersistenceResult<Option<ProjectionMorphList>> {
    use diesel_async::AsyncConnection as _;
    let mut conn = crate::pg_conn(pool).await?;
    conn.transaction::<_, crate::PgTransactionError, _>(async move |conn| {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, realm).await?;
        Ok(list_in_connection(
            conn,
            realm,
            actor,
            station,
            include_terminal,
            chrono::Utc::now(),
        )
        .await?
        .map(|(value, _)| value))
    })
    .await
    .map_err(crate::PgTransactionError::into_persistence)
}

pub(crate) async fn document_for_actor(
    pool: &crate::PgPool,
    realm: &RealmId,
    morph: &arkret_wire::MorphId,
    actor: &ActorId,
    station: &DidCoreId,
) -> PersistenceResult<Option<DocumentMorphProjectionOutcome>> {
    use diesel_async::AsyncConnection as _;
    let mut conn = crate::pg_conn(pool).await?;
    conn.transaction::<_, crate::PgTransactionError, _>(async move |conn| {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, realm).await?;
        Ok(
            document_in_connection(conn, realm, morph, actor, station, chrono::Utc::now())
                .await?
                .map(|(value, _)| value),
        )
    })
    .await
    .map_err(crate::PgTransactionError::into_persistence)
}

pub(crate) type NativeTimeProof = (
    crate::realm_authorization_cut::RealmAuthorizationCut,
    Option<arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef>,
    NativeReadFact,
);

pub(crate) async fn qualify_delivery_facts(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    controller: &arkret_wire::AccountId,
    facts: Vec<NativeReadFact>,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Vec<NativeTimeProof>> {
    use arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation;
    let mut proofs = Vec::new();
    for fact in facts {
        let realm = fact
            .target
            .realm_id
            .as_ref()
            .ok_or_else(|| unavailable("delivery fact has no Realm"))?;
        let resources =
            crate::agent_management_admission::selector_content_resources(realm, &fact.target)?;
        for operation in [AgentPolicyOperation::Read, AgentPolicyOperation::Deliver] {
            crate::agent_management_admission::require_content_snapshot_in_connection(
                conn,
                realm,
                fact.circle.as_ref(),
                controller,
                account,
                operation,
                fact.action,
                &resources,
                at,
            )
            .await?;
        }
        for recipient in [account, controller] {
            let actor = ActorId::account(recipient.clone());
            let cut =
                crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, realm, &actor)
                    .await?;
            let source = if recipient == account
                && fact.action != arkret_wire::CapabilityActionId::MorphRead
            {
                crate::realm_authorization_cut::owned_source_in_connection(
                    conn, realm, &actor, at, false,
                )
                .await?
            } else {
                None
            };
            cut.require_native_projection_read(
                &fact.target,
                &fact.facts,
                fact.action,
                source.clone(),
                at,
            )?;
            if !visible(
                conn,
                realm,
                fact.circle.as_ref().map(|id| id.as_str()),
                &actor,
            )
            .await?
            {
                return Err(unavailable(
                    "projection source is no longer visible to its recipient",
                ));
            }
            proofs.push((cut, source, fact.clone()));
        }
    }
    Ok(proofs)
}

fn canonical_same<T: serde::Serialize>(left: &T, right: &T) -> PersistenceResult<bool> {
    Ok(
        arkret_canonical::canonical_json_bytes(left).map_err(unavailable)?
            == arkret_canonical::canonical_json_bytes(right).map_err(unavailable)?,
    )
}

pub(crate) fn owner_covers_document(
    output: &DocumentMorphProjectionOutcome,
    owner: &DocumentMorphProjectionOutcome,
) -> PersistenceResult<bool> {
    if !canonical_same(&output.document, &owner.document)? {
        return Ok(false);
    }
    for (rows, owner_rows) in [
        (&output.versions, &owner.versions),
        (&output.comments, &owner.comments),
    ] {
        for row in rows {
            let mut found = false;
            for owner_row in owner_rows {
                if canonical_same(row, owner_row)? {
                    found = true;
                    break;
                }
            }
            if !found {
                return Ok(false);
            }
        }
    }
    for row in &output.relations {
        let Some(owner_row) = owner
            .relations
            .iter()
            .find(|candidate| candidate.get("relation_id") == row.get("relation_id"))
        else {
            return Ok(false);
        };
        if row.get("locked") == Some(&serde_json::Value::Bool(true)) {
            // A locked row intentionally contains no foreign endpoint or fields.
            // The controller must at least see this relation's complete identity.
            for key in ["relation_id", "relation_kind", "state"] {
                if row.get(key) != owner_row.get(key) {
                    return Ok(false);
                }
            }
        } else if !canonical_same(row, owner_row)? {
            return Ok(false);
        }
    }
    Ok(true)
}

type HeldConnection = diesel_async::pooled_connection::deadpool::Object<AsyncPgConnection>;
struct OrdinaryMorphGuard {
    connection: Option<HeldConnection>,
    runtime: tokio::runtime::Handle,
    at: chrono::DateTime<chrono::Utc>,
    expires: Option<chrono::DateTime<chrono::Utc>>,
    proofs: Vec<NativeTimeProof>,
}
#[async_trait::async_trait]
impl coland_storage::AccountContentDeliveryGuard for OrdinaryMorphGuard {
    fn permits_handoff(&self) -> bool {
        let now = chrono::Utc::now();
        now >= self.at
            && self.expires.is_none_or(|expires| now < expires)
            && self.proofs.iter().all(|(cut, source, fact)| {
                cut.time_sources_unchanged(self.at, now)
                    && cut
                        .require_native_projection_read(
                            &fact.target,
                            &fact.facts,
                            fact.action,
                            source.clone(),
                            now,
                        )
                        .is_ok()
            })
    }
    async fn finish(mut self: Box<Self>) -> PersistenceResult<()> {
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| unavailable("Morph read cut is not held"))?;
        sql_query("ROLLBACK")
            .execute(&mut **connection)
            .await
            .map_err(PersistenceError::database)?;
        drop(self.connection.take());
        Ok(())
    }
}
impl Drop for OrdinaryMorphGuard {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            let connection = HeldConnection::take(connection);
            let cancel = connection.cancel_token();
            drop(connection);
            self.runtime.spawn(async move {
                let _ = cancel.cancel_query(tokio_postgres::NoTls).await;
            });
        }
    }
}

#[derive(QueryableByName)]
struct HumanGenesisRow {
    #[diesel(sql_type = diesel::sql_types::Binary)]
    exact_request_body: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    result_json: serde_json::Value,
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
    #[diesel(sql_type = Text)]
    genesis_event_id: String,
    #[diesel(sql_type = Text)]
    current_event_id: String,
    #[diesel(sql_type = Jsonb)]
    projection: serde_json::Value,
}
#[derive(QueryableByName)]
struct PcrCommitRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
}
#[derive(QueryableByName)]
struct HumanRealmRow {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
}
pub(crate) async fn human_realm_in_connection(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
) -> PersistenceResult<RealmId> {
    let row = sql_query("SELECT r.pcr_realm_id FROM principal_resolutions r JOIN pcr_genesis_units g ON g.realm_id=r.pcr_realm_id AND g.principal_id=r.principal_id AND g.station_id=r.station_id WHERE r.principal_id=$1 AND r.station_id=$2")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<HumanRealmRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| unavailable("ordinary Morph caller has no accepted human registration anchor"))?;
    row.pcr_realm_id.parse().map_err(unavailable)
}
pub(crate) async fn require_accepted_human_identity(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    held_pcr: &RealmId,
    station: &DidCoreId,
    observation: Option<&coland_storage::AccountStatusCurrentObservation>,
) -> PersistenceResult<()> {
    require_accepted_human_pcr_in_connection(conn, account, held_pcr).await?;
    require_current_human_account(conn, account, held_pcr, station, observation).await
}

/// Verifies the complete accepted PCR identity independently of AA lifecycle status.
pub(crate) async fn require_accepted_human_pcr_in_connection(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    held_pcr: &RealmId,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::principal_operations::{
        PcrGenesisAdmissionInput, PcrGenesisAdmissionOutcome,
    };
    // Positive closed human registration evidence, not an absent Agent row or
    // a non-authoritative Actor Profile classification.
    let row = sql_query("SELECT g.exact_request_body,g.result_json,r.pcr_realm_id,r.genesis_event_id,r.current_event_id,r.projection FROM pcr_genesis_units g \
        JOIN principal_resolutions r ON r.principal_id=g.principal_id AND r.station_id=g.station_id AND r.pcr_realm_id=g.realm_id \
        WHERE g.principal_id=$1 AND g.station_id=$2 FOR SHARE OF g,r")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<HumanGenesisRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||unavailable("ordinary Morph caller has no accepted human registration anchor"))?;
    let exact_request_body = row.exact_request_body;
    let result_json = row.result_json;
    // Decode and validate the original closed registration off the I/O poll
    // stack. The complete typed material returns to this same locked cut.
    let (request, result) = tokio::task::spawn_blocking(move || -> PersistenceResult<_> {
        let request: Box<PcrGenesisAdmissionInput> =
            serde_json::from_slice(&exact_request_body).map_err(unavailable)?;
        let result: Box<PcrGenesisAdmissionOutcome> =
            serde_json::from_value(result_json).map_err(unavailable)?;
        result.validate_against(&request).map_err(unavailable)?;
        Ok((request, result))
    })
    .await
    .map_err(|error| {
        unavailable(format!(
            "accepted human registration verification task failed: {error}"
        ))
    })??;
    if request.principal_id != account.principal_id
        || request.account_authority_id != account.station_id
        || request.pcr_realm_id != *held_pcr
        || row.pcr_realm_id != held_pcr.as_str()
    {
        return Err(unavailable(
            "human registration binds a different complete Account",
        ));
    }
    for (event, commit) in request.genesis_unit.events.iter().zip(&result.commits) {
        let accepted =
            crate::committed_disclosure::accepted_full_event_in_connection(conn, &event.event_id)
                .await?
                .ok_or_else(|| unavailable("human registration unit is not committed"))?;
        if accepted.event != *event || accepted.commit != *commit {
            return Err(unavailable(
                "human registration differs from its accepted unit",
            ));
        }
    }
    let genesis_id = row.genesis_event_id.parse().map_err(unavailable)?;
    let current_id = row.current_event_id.parse().map_err(unavailable)?;
    let genesis = crate::committed_disclosure::accepted_full_event_in_connection(conn, &genesis_id)
        .await?
        .ok_or_else(|| unavailable("human current genesis source is unavailable"))?;
    let current = crate::committed_disclosure::accepted_full_event_in_connection(conn, &current_id)
        .await?
        .ok_or_else(|| unavailable("human current resolution source is unavailable"))?;
    coland_storage::validate_principal_resolution_record(
        &coland_storage::PrincipalResolutionRecord {
            account_id: account.clone(),
            pcr_realm_id: held_pcr.clone(),
            genesis_event: genesis.event,
            current_event: current.event,
            projection: serde_json::from_value(row.projection).map_err(unavailable)?,
        },
    )?;
    let authority = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(held_pcr.as_str())
        .get_result::<Governor>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    if authority.service_id != account.station_id.as_str() {
        return Err(unavailable(
            "human PCR governing identity differs from its Account binding",
        ));
    }
    let rows = sql_query("SELECT commit_json FROM realm_commits WHERE realm_id=$1 ORDER BY stream_key COLLATE \"C\",stream_position")
        .bind::<Text,_>(held_pcr.as_str()).load::<PcrCommitRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut streams = CommitStreamProjection::new();
    let mut originals = BTreeMap::new();
    for row in rows {
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(row.commit_json).map_err(unavailable)?;
        if commit.realm_id != *held_pcr {
            return Err(unavailable(
                "human PCR Commit Realm differs from current binding",
            ));
        }
        let full =
            crate::committed_disclosure::accepted_full_event_in_connection(conn, &commit.event_ref)
                .await?
                .ok_or_else(|| unavailable("human PCR current original is unavailable"))?;
        if full.commit != commit {
            return Err(unavailable(
                "human PCR current Commit differs from its accepted pair",
            ));
        }
        streams.apply_committed(full.clone()).map_err(unavailable)?;
        if originals
            .insert(full.event.event_id.clone(), full)
            .is_some()
        {
            return Err(unavailable("human PCR accepted source is not unique"));
        }
    }
    require_complete_held_sources(conn, held_pcr, &streams, &originals).await?;
    let terminal = sql_query("SELECT EXISTS(SELECT 1 FROM committed_events e JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=e.realm_id WHERE e.realm_id=$1 AND e.kind IN ('ak.realm.tombstone','ak.realm.destroy')) AS present")
        .bind::<Text,_>(held_pcr.as_str()).get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if terminal.present {
        return Err(unavailable("human PCR current is terminal"));
    }
    Ok(())
}

#[derive(QueryableByName)]
struct AccountGateRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}
#[derive(QueryableByName)]
struct LifecycleRow {
    #[diesel(sql_type = Text)]
    state: String,
}
#[derive(QueryableByName)]
struct StatusHeadRow {
    #[diesel(sql_type = Jsonb)]
    record: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    receipt: serde_json::Value,
}
pub(crate) async fn require_observed_account_status_in_connection(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    pcr: &RealmId,
    station: &DidCoreId,
    observation: Option<&coland_storage::AccountStatusCurrentObservation>,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::objects::account_status::AccountStatus;
    if require_observed_account_status_binding_in_connection(
        conn,
        account,
        pcr,
        station,
        observation,
    )
    .await?
        != AccountStatus::Active
    {
        return Err(unavailable(
            "human current Account status is not active or bound",
        ));
    }
    Ok(())
}

/// Returns a lifecycle status only after its complete current observation is bound.
pub(crate) async fn require_observed_account_status_binding_in_connection(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    pcr: &RealmId,
    station: &DidCoreId,
    observation: Option<&coland_storage::AccountStatusCurrentObservation>,
) -> PersistenceResult<arkret_models_collaboration::objects::account_status::AccountStatus> {
    use arkret_models_collaboration::account_status::{AccountStatusReceipt, AccountStatusRecord};
    // Reuse the original replica writer's exact complete-Account lock, including
    // the first successor. PCR genesis establishes only the initial binding.
    let lock = format!("account-status:{}:{account}", account.station_id);
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(lock)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let status = sql_query("SELECT record,receipt FROM account_status_replica_records WHERE account_authority_id=$1 AND account_id=$2 ORDER BY status_seq DESC LIMIT 1")
        .bind::<Text,_>(account.station_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(account).map_err(unavailable)?)
        .get_result::<StatusHeadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let status = status
        .ok_or_else(|| unavailable("human Account Authority lifecycle head is unavailable"))?;
    {
        let record: AccountStatusRecord =
            serde_json::from_value(status.record).map_err(unavailable)?;
        let receipt: AccountStatusReceipt =
            serde_json::from_value(status.receipt).map_err(unavailable)?;
        receipt.validate_for_record(&record).map_err(unavailable)?;
        let observation = observation.ok_or_else(|| {
            unavailable("human Account Authority current observation is unavailable")
        })?;
        if !observation.is_completed() || observation.record() != &record {
            return Err(unavailable(
                "human Account Authority head changed after current resolve",
            ));
        }
        if record.account_id != *account
            || record.account_authority_id != account.station_id
            || record.principal_control_realm_id != *pcr
            || receipt.receiver_id != *station
        {
            return Err(unavailable("human current Account status is not bound"));
        }
        Ok(record.status)
    }
}

pub(crate) async fn require_current_human_account(
    conn: &mut AsyncPgConnection,
    account: &arkret_wire::AccountId,
    pcr: &RealmId,
    station: &DidCoreId,
    observation: Option<&coland_storage::AccountStatusCurrentObservation>,
) -> PersistenceResult<()> {
    require_observed_account_status_in_connection(conn, account, pcr, station, observation).await?;
    // Optional product projections cannot create identity or replace the native
    // binding. If present, lock both their original lifecycle-writer sources.
    let product = sql_query("SELECT disabled_at IS NULL AS present FROM accounts WHERE principal_id=$1 AND station_id=$2 FOR SHARE")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<AccountGateRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if product.is_some_and(|row| !row.present) {
        return Err(unavailable("human product Account is disabled"));
    }
    let lifecycle = sql_query("SELECT l.state FROM account_lifecycle l JOIN accounts a ON a.pk=l.account_pk WHERE a.principal_id=$1 AND a.station_id=$2 FOR SHARE OF l")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<LifecycleRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if lifecycle.is_some_and(|row| row.state != "active") {
        return Err(unavailable("human current Account lifecycle is not active"));
    }
    Ok(())
}

pub(crate) async fn ordinary_delivery_guard(
    pool: &crate::PgPool,
    account: &arkret_wire::AccountId,
    station: &DidCoreId,
    input: &coland_storage::AccountContentDeliveryInput,
) -> PersistenceResult<Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>> {
    use coland_storage::AccountContentDeliveryGuard as _;
    if input.morph_lists.is_empty()
        && input.morph_documents.is_empty()
        && input.morph_absences.is_empty()
    {
        return Ok(None);
    }
    // An Agent/Applet/unknown holder cannot substitute the human branch when
    // its current endpoint/provision/qualified scope evidence is unavailable.
    if input.agent_endpoint.is_some() || input.agent_session_scope.is_some() {
        return Err(unavailable(
            "ordinary Morph Agent endpoint has no complete owned delivery cut",
        ));
    }
    let mut guard = Box::new(OrdinaryMorphGuard {
        connection: Some(crate::pg_conn(pool).await?),
        runtime: tokio::runtime::Handle::current(),
        at: chrono::Utc::now(),
        expires: input.credential_expires_at,
        proofs: Vec::new(),
    });
    let conn = guard
        .connection
        .as_mut()
        .ok_or_else(|| unavailable("Morph cut is unavailable"))?;
    sql_query("BEGIN")
        .execute(&mut **conn)
        .await
        .map_err(PersistenceError::database)?;
    let pcr = human_realm_in_connection(conn, account).await?;
    let realms = input
        .morph_lists
        .iter()
        .map(|(realm, ..)| realm)
        .chain(input.morph_documents.iter().map(|(realm, ..)| realm))
        .chain(input.morph_absences.iter().map(|(realm, ..)| realm))
        .chain(std::iter::once(&pcr))
        .collect::<BTreeSet<_>>();
    for realm in realms {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, realm).await?;
        if crate::realm_authorization_cut::is_owned_agent_in_connection(conn, realm, account)
            .await?
        {
            return Err(unavailable("Morph caller now requires the owned Agent cut"));
        }
    }
    require_accepted_human_identity(
        conn,
        account,
        &pcr,
        station,
        input
            .account_status_observations
            .iter()
            .find(|observation| &observation.record().account_id == account),
    )
    .await?;
    let actor = ActorId::account(account.clone());
    let at = chrono::Utc::now();
    let mut all_facts = Vec::new();
    for (realm, terminal, output) in &input.morph_lists {
        let (fresh, facts) = list_in_connection(conn, realm, &actor, station, *terminal, at)
            .await?
            .ok_or_else(|| unavailable("ordinary Morph actor current is unavailable"))?;
        if !canonical_same(output, &fresh)? {
            return Err(unavailable(
                "ordinary Morph output changed, including empty list",
            ));
        }
        all_facts.extend(facts);
    }
    for (realm, morph, output) in &input.morph_documents {
        let (fresh, facts) = document_in_connection(conn, realm, morph, &actor, station, at)
            .await?
            .ok_or_else(|| unavailable("ordinary document current is unavailable"))?;
        if !canonical_same(output, &fresh)? {
            return Err(unavailable("ordinary complete document output changed"));
        }
        all_facts.extend(facts);
    }
    for (realm, morph) in &input.morph_absences {
        all_facts
            .extend(document_absence_in_connection(conn, realm, morph, &actor, station, at).await?);
    }
    let mut proofs = Vec::new();
    for fact in all_facts {
        let realm = fact
            .target
            .realm_id
            .as_ref()
            .ok_or_else(|| unavailable("ordinary Morph fact has no Realm"))?;
        let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, realm, &actor)
            .await?;
        cut.require_native_projection_read(&fact.target, &fact.facts, fact.action, None, at)?;
        proofs.push((cut, None, fact));
    }
    guard.at = at;
    guard.proofs = proofs;
    if !guard.permits_handoff() {
        return Err(unavailable(
            "ordinary Morph permission expired before handoff",
        ));
    }
    Ok(Some(guard))
}

#[cfg(test)]
#[path = "../../test-support/src/device_authorization_history.rs"]
#[expect(
    dead_code,
    reason = "Only accepted human genesis is needed by the Morph read fixture."
)]
mod device_authorization_history;
#[cfg(test)]
#[path = "../../test-support/src/pcr_genesis.rs"]
#[expect(
    dead_code,
    reason = "Only accepted human genesis is needed by the Morph read fixture."
)]
mod pcr_genesis;

#[cfg(test)]
mod tests {
    use arkret_wire::{Event, RealmCommit, ScopeRef};
    use coland_storage::{IdentityStoreRegistry as _, SyncStoreRegistry as _};
    use diesel::sql_types::Binary;
    use serde_json::{Value, json};

    use super::*;

    // Trusted native import fixture: this observes the verified local fixture
    // ledger. It is not evidence that a remote HTTP issuer was contacted.
    async fn fixture_delivery_guard(
        pool: &crate::PgPool,
        account: &arkret_wire::AccountId,
        station: &DidCoreId,
        input: &coland_storage::AccountContentDeliveryInput,
    ) -> PersistenceResult<Option<Box<dyn coland_storage::AccountContentDeliveryGuard>>> {
        let persistence = crate::PgPersistenceStore::new(pool.clone());
        let mut input = input.clone();
        input.account_status_observations = persistence
            .account_status_replicas()
            .current(account.station_id.as_str(), account)
            .await?
            .map(coland_storage::AccountStatusCurrentObservation::after_authenticated_resolve)
            .into_iter()
            .collect();
        ordinary_delivery_guard(pool, account, station, &input).await
    }

    async fn morph_database() -> crate::test_database::TestDatabase {
        let database = crate::test_database::TestDatabase::lease().await;
        // Match the original serving-identity prerequisite for the device
        // inventory; this is not an Account product-row authorization gate.
        database.bind_device_inventory_station(station().as_str());
        database
    }

    fn station() -> DidCoreId {
        "ak:did_core:web:morph-station.example".parse().unwrap()
    }
    fn actor(principal: &str) -> ActorId {
        ActorId::account(arkret_wire::AccountId::new(
            principal.parse().unwrap(),
            station(),
        ))
    }
    fn at(position: u64) -> chrono::DateTime<chrono::Utc> {
        "2026-10-05T12:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
            + chrono::TimeDelta::seconds(position as i64)
    }
    fn genesis() -> Event {
        let payload: arkret_models_collaboration::events_payloads::realm::RealmCreatePayload =
            serde_json::from_value(json!({"object":{
                "schema":"ak.schema.realm_genesis.v1","purpose":"collaboration",
                "genesis_salt":arkret_canonical::base64url_encode([91u8;32]),
                "trust_domain":"ak:trust_domain:morph.example","security_class":"high_assurance",
                "governance_station_id":station(),"initial_join_rule":"invite",
                "initial_history_access":"since_join","initial_discoverability":"invite_only"
            }}))
            .unwrap();
        arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::RealmCreate.as_str(),
            ScopeRef::RealmGenesis,
            actor("ak:did_core:web:morph-controller.example"),
            payload.to_value().unwrap(),
            at(0),
        )
        .unwrap()
    }
    fn event(kind: EventKind, realm: &RealmId, payload: Value, position: u64) -> Event {
        arkret_wire::test_support::raw_event_for_actor_at(
            kind.as_str(),
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            actor("ak:did_core:web:morph-controller.example"),
            payload,
            at(position),
        )
        .unwrap()
    }
    // Object positions are relative to the accepted Realm fixture's opening.
    // The explicit history-policy and member-join sources occupy positions 1/2.
    fn morph_position(event: &Event, position: u64) -> u64 {
        if event.realm_id == genesis().realm_id && position > 0 {
            position + 2
        } else {
            position
        }
    }
    fn commit(event: &Event, position: u64) -> RealmCommit {
        commit_at(event, morph_position(event, position))
    }
    fn fixture_commit_id(realm: &RealmId, position: u64) -> arkret_wire::RealmCommitId {
        arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            format!("{realm}:{position}").as_bytes(),
        ))
    }
    fn commit_at(event: &Event, position: u64) -> RealmCommit {
        RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: fixture_commit_id(&event.realm_id, position),
            realm_id: event.realm_id.clone(),
            stream_ref: CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            },
            stream_position: position,
            previous_commit_ref: position
                .checked_sub(1)
                .map(|prior| fixture_commit_id(&event.realm_id, prior)),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                event.event_id.clone(),
            ),
            committed_at: event.created_at,
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:morph-station.example#authority",
                )
                .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "aa".repeat(32)))
                    .unwrap(),
                created_at: event.created_at,
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
            },
        }
    }
    // Imported accepted history exercises original PG readers and the common
    // production reducer. It does not claim producer/signature HTTP admission.
    async fn insert_history(conn: &mut AsyncPgConnection, event: &Event, position: u64) {
        insert_history_at(conn, event, morph_position(event, position)).await;
    }
    async fn insert_history_at(conn: &mut AsyncPgConnection, event: &Event, position: u64) {
        let commit = commit_at(event, position);
        let realm_pk = crate::realm_identity::ensure_realm_pk(conn, event.realm_id.as_str())
            .await
            .unwrap();
        sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,committed_at,realm_pk) VALUES($1,1,$2,$3,$4,$5,$6,$7,$8,'committed',$9,$10)")
            .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).bind::<Binary,_>(event.event_id.digest_bytes().to_vec())
            .bind::<Text,_>(event.actor_id.to_string()).bind::<Text,_>(event.realm_id.as_str())
            .bind::<Jsonb,_>(json!(event.scope_ref)).bind::<Text,_>(event.kind.as_str())
            .bind::<Binary,_>(arkret_canonical::canonical_json_bytes(event).unwrap()).bind::<Jsonb,_>(json!(event))
            .bind::<Timestamptz,_>(commit.committed_at).bind::<BigInt,_>(realm_pk).execute(&mut *conn).await.unwrap();
        sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) SELECT $1,$2,$3,$4,$5,$6,pk,0,$7,$8 FROM canonical_events WHERE id=$9")
            .bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(event.realm_id.as_str())
            .bind::<Text,_>(crate::authority_commit::stream_key(&commit.stream_ref).unwrap())
            .bind::<Jsonb,_>(json!(commit.stream_ref)).bind::<BigInt,_>(position as i64)
            .bind::<Nullable<Text>,_>(commit.previous_commit_ref.as_ref().map(|id|id.as_str()))
            .bind::<Jsonb,_>(json!(commit)).bind::<Timestamptz,_>(event.created_at)
            .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).execute(&mut *conn).await.unwrap();
        crate::projection::append_projection_event_in_transaction(
            conn,
            coland_storage::ProjectionEventRecord {
                event_id: event.event_id.to_string(),
                realm_id: event.realm_id.to_string(),
                event_kind: event.kind.to_string(),
                operation_kind: "create".to_owned(),
                operation_id: Some(crate::ids::format_typed_uuid(
                    "operation",
                    &uuid::Uuid::now_v7(),
                )),
                sender: Some(event.actor_id.to_string()),
                payload: json!(event.payload),
                created_at: event.created_at,
                received_at: event.created_at,
            },
        )
        .await
        .unwrap();
    }
    async fn seed(conn: &mut AsyncPgConnection, reader: &ActorId) -> Event {
        let opening = genesis();
        let realm = &opening.realm_id;
        sql_query("INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref) VALUES($1,0,$2,'{}')")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(station().as_str()).execute(&mut *conn).await.unwrap();
        insert_history(conn, &opening, 0).await;
        sql_query("INSERT INTO realm_authority_root_current_results(realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref,current_commit_id,current_stream_position,updated_at) VALUES($1,$2,0,0,$3,$4,0,$5)")
            .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(json!(opening.actor_id))
            .bind::<Text,_>(opening.event_id.as_str()).bind::<Text,_>(commit(&opening,0).commit_id.as_str())
            .bind::<Timestamptz,_>(at(0)).execute(&mut *conn).await.unwrap();
        // Import the accepted bootstrap facets and derive their original
        // current rows. Missing policy evidence must continue hiding history.
        let history = event(
            EventKind::RealmHistoryAccess,
            realm,
            json!({"from":null,"to":"since_join"}),
            0,
        );
        arkret_schema::validate_event_wire_schema(&history).unwrap();
        insert_history_at(conn, &history, 1).await;
        crate::realm_bootstrap_current_results::commit_ordinary_bootstrap_singleton_current_result_in_connection(
            conn, &history, &commit_at(&history, 1),
        ).await.unwrap();
        let member = event(
            EventKind::MemberState,
            realm,
            json!({"member_id":reader,"membership":"join"}),
            0,
        );
        arkret_schema::validate_event_wire_schema(&member).unwrap();
        insert_history_at(conn, &member, 2).await;
        crate::unit_of_work::commit_parent_membership_current_results(
            conn,
            &member,
            &commit_at(&member, 2),
        )
        .await
        .unwrap();
        opening
    }
    async fn grant(
        conn: &mut AsyncPgConnection,
        opening: &Event,
        reader: &ActorId,
        actions: &[&str],
    ) {
        let source =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [51; 32]);
        let grant = arkret_wire::GrantId::from_event_id(&source);
        let root = json!({"kind":"realm_root","realm_id":opening.realm_id,
            "authority_event_ref":opening.event_id,"authority_generation":0});
        let value = json!({"id":grant,"schema":"ak.schema.capability.v1","realm_id":opening.realm_id,
            "issuer_id":opening.actor_id,"subject":reader,"actions":actions,
            "resources":[{"kind":"realm","realm_id":opening.realm_id}],
            "issuer_authority_refs":[root],"authority_depth":1,"authority_root_refs":[root],
            "issued_at":arkret_canonical::format_timestamp_canonical(at(0)),"status":"active"});
        sql_query("INSERT INTO capability_grant_current_results(realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value,updated_at) VALUES($1,$2,'active',$3,$4,$5,0,$6,$7) ON CONFLICT(realm_id,grant_id) DO UPDATE SET value=EXCLUDED.value")
            .bind::<Text,_>(opening.realm_id.as_str()).bind::<Text,_>(grant.as_str())
            .bind::<Text,_>(source.as_str()).bind::<Text,_>(commit(opening,0).commit_id.as_str())
            .bind::<Jsonb,_>(json!(CommitStreamRef::Realm {realm_id:opening.realm_id.clone()}))
            .bind::<Jsonb,_>(value).bind::<Timestamptz,_>(at(0)).execute(&mut *conn).await.unwrap();
    }
    async fn create_morph(conn: &mut AsyncPgConnection, realm: &RealmId) -> Event {
        use arkret_models_collaboration::events_payloads::morph::MorphCreatePayload;
        use arkret_models_collaboration::objects::profiles::Morph;
        let mut object = Morph::new(
            arkret_wire::MorphId::from_event_id(&genesis().event_id),
            realm.clone(),
            "document",
            actor("ak:did_core:web:morph-controller.example"),
        )
        .with_metadata_title("Original");
        // The placeholder passed to the SDK constructor is never authored:
        // the create Event derives its own id; lifecycle is reducer-managed.
        object.id = None;
        object.state = None;
        object.created_at = at(1);
        object.fields.insert("body".to_owned(), json!("Body"));
        let payload = serde_json::to_value(MorphCreatePayload { object }).unwrap();
        let event = event(EventKind::MorphCreate, realm, payload, 1);
        insert_history(conn, &event, 1).await;
        event
    }

    async fn human_document_fixture(
        database: &crate::test_database::TestDatabase,
    ) -> (
        super::pcr_genesis::PcrGenesisFixture,
        Event,
        Event,
        DocumentMorphProjectionOutcome,
    ) {
        let persistence = crate::PgPersistenceStore::new(database.pool());
        let identity = super::pcr_genesis::PcrGenesisFixture::new(
            "did:web:morph-station.example".parse().unwrap(),
        );
        identity.admit_into(&persistence).await.unwrap();
        import_human_status_genesis(&database.pool(), &persistence, &identity).await;
        let reader = ActorId::account(identity.history.account.clone());
        let mut conn = database.pool().get().await.unwrap();
        let opening = seed(&mut conn, &reader).await;
        grant(
            &mut conn,
            &opening,
            &reader,
            &[
                "ak.morph.read",
                "ak.object.read_metadata",
                "ak.object.read_content",
                "ak.object.read_history",
            ],
        )
        .await;
        let created = create_morph(&mut conn, &opening.realm_id).await;
        let morph = arkret_wire::MorphId::from_event_id(&created.event_id);
        let output = document_in_connection(
            &mut conn,
            &opening.realm_id,
            &morph,
            &reader,
            &station(),
            at(3),
        )
        .await
        .unwrap()
        .unwrap()
        .0;
        (identity, opening, created, output)
    }

    #[tokio::test]
    async fn native_morph_document_cold_body_is_typed_and_has_no_fabricated_checkpoint() {
        let database = morph_database().await;
        let (identity, opening, created, original) = human_document_fixture(&database).await;
        let store = crate::PgAuthorityCommitStore {
            pool: database.pool(),
        };
        use coland_storage::AuthorityCommitStore as _;
        let cold = store
            .document_morph_for_actor(
                &opening.realm_id,
                &arkret_wire::MorphId::from_event_id(&created.event_id),
                &ActorId::account(identity.history.account.clone()),
                &station(),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(canonical_same(&original, &cold).unwrap());
        assert_eq!(cold.document.body, json!("Body"));
        assert_eq!(cold.document.title.as_deref(), Some("Original"));
        assert!(cold.relations.is_empty());
        assert!(cold.comments.is_empty());
        assert!(cold.checkpoint.is_none());
        let json = serde_json::to_value(cold).unwrap();
        assert!(json.get("cursor_presence").is_none());
        assert!(json.get("cursor_presence_entries").is_none());
    }

    #[tokio::test]
    async fn native_morph_document_body_requires_additive_content_permission() {
        let database = morph_database().await;
        let (identity, opening, created, _) = human_document_fixture(&database).await;
        let reader = ActorId::account(identity.history.account.clone());
        let mut conn = database.pool().get().await.unwrap();
        grant(
            &mut conn,
            &opening,
            &reader,
            &[
                "ak.morph.read",
                "ak.object.read_metadata",
                "ak.object.read_history",
            ],
        )
        .await;
        assert!(
            document_in_connection(
                &mut conn,
                &opening.realm_id,
                &arkret_wire::MorphId::from_event_id(&created.event_id),
                &reader,
                &station(),
                at(3)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn native_morph_document_full_output_substitution_cannot_reach_handoff() {
        let database = morph_database().await;
        let (identity, opening, created, output) = human_document_fixture(&database).await;
        for replacement in [json!("Different body"), json!(null)] {
            let mut candidate = output.clone();
            candidate.document.body = replacement;
            let input = coland_storage::AccountContentDeliveryInput {
                morph_documents: vec![(
                    opening.realm_id.clone(),
                    arkret_wire::MorphId::from_event_id(&created.event_id),
                    candidate,
                )],
                ..Default::default()
            };
            assert!(
                fixture_delivery_guard(
                    &database.pool(),
                    &identity.history.account,
                    &station(),
                    &input
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn native_morph_document_member_loss_rejects_previous_exact_output() {
        let database = morph_database().await;
        let (identity, opening, created, output) = human_document_fixture(&database).await;
        let mut conn = database.pool().get().await.unwrap();
        sql_query("UPDATE member_state_current_results SET membership='leave',value=jsonb_set(value,'{membership}','\"leave\"'::jsonb) WHERE realm_id=$1")
            .bind::<Text, _>(opening.realm_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        let input = coland_storage::AccountContentDeliveryInput {
            morph_documents: vec![(
                opening.realm_id,
                arkret_wire::MorphId::from_event_id(&created.event_id),
                output,
            )],
            ..Default::default()
        };
        assert!(
            fixture_delivery_guard(
                &database.pool(),
                &identity.history.account,
                &station(),
                &input
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn native_morph_document_missing_original_mapping_refuses_body() {
        let database = morph_database().await;
        let (identity, opening, created, _) = human_document_fixture(&database).await;
        let mut conn = database.pool().get().await.unwrap();
        sql_query("DELETE FROM projection_events WHERE event_pk=(SELECT pk FROM canonical_events WHERE envelope->>'event_id'=$1)")
            .bind::<Text,_>(created.event_id.as_str()).execute(&mut *conn).await.unwrap();
        assert!(
            document_in_connection(
                &mut conn,
                &opening.realm_id,
                &arkret_wire::MorphId::from_event_id(&created.event_id),
                &ActorId::account(identity.history.account.clone()),
                &station(),
                at(3)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn native_morph_document_expired_credential_cannot_publish() {
        let database = morph_database().await;
        let (identity, opening, created, output) = human_document_fixture(&database).await;
        let input = coland_storage::AccountContentDeliveryInput {
            morph_documents: vec![(
                opening.realm_id,
                arkret_wire::MorphId::from_event_id(&created.event_id),
                output,
            )],
            credential_expires_at: Some(chrono::Utc::now() - chrono::TimeDelta::seconds(1)),
            ..Default::default()
        };
        assert!(
            fixture_delivery_guard(
                &database.pool(),
                &identity.history.account,
                &station(),
                &input
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn native_morph_document_held_cut_blocks_original_authority_writer_until_finish() {
        let database = morph_database().await;
        let (identity, opening, created, output) = human_document_fixture(&database).await;
        let input = coland_storage::AccountContentDeliveryInput {
            morph_documents: vec![(
                opening.realm_id.clone(),
                arkret_wire::MorphId::from_event_id(&created.event_id),
                output,
            )],
            ..Default::default()
        };
        let guard = fixture_delivery_guard(
            &database.pool(),
            &identity.history.account,
            &station(),
            &input,
        )
        .await
        .unwrap()
        .unwrap();
        let pool = database.pool();
        let realm = opening.realm_id;
        let mut writer = tokio::spawn(async move {
            let mut conn = pool.get().await.unwrap();
            sql_query("BEGIN").execute(&mut *conn).await.unwrap();
            crate::realm_authorization_cut::lock_realm_authorization_cut(&mut conn, &realm)
                .await
                .unwrap();
            sql_query("COMMIT").execute(&mut *conn).await.unwrap();
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut writer)
                .await
                .is_err()
        );
        assert!(guard.permits_handoff());
        guard.finish().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), writer)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn native_morph_document_absence_is_rechecked_and_hidden_existing_is_not_absent() {
        let database = morph_database().await;
        let (_, identity, empty) = human_list_fixture(&database).await;
        let realm = empty.morph_lists[0].0.clone();
        let reader = ActorId::account(identity.history.account.clone());
        let mut conn = database.pool().get().await.unwrap();
        let absent = arkret_wire::MorphId::from_event_id(&genesis().event_id);
        let facts =
            document_absence_in_connection(&mut conn, &realm, &absent, &reader, &station(), at(3))
                .await
                .unwrap();
        assert_eq!(facts.len(), 2);
        drop(conn);
        let input = coland_storage::AccountContentDeliveryInput {
            morph_absences: vec![(realm.clone(), absent)],
            ..Default::default()
        };
        let guard = fixture_delivery_guard(
            &database.pool(),
            &identity.history.account,
            &station(),
            &input,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(guard.permits_handoff());
        guard.finish().await.unwrap();
        let mut conn = database.pool().get().await.unwrap();
        let created = create_morph(&mut conn, &realm).await;
        let exists = arkret_wire::MorphId::from_event_id(&created.event_id);
        assert!(
            document_absence_in_connection(&mut conn, &realm, &exists, &reader, &station(), at(3))
                .await
                .is_err()
        );
        sql_query("DELETE FROM realm_commits WHERE realm_id=$1 AND stream_position=3")
            .bind::<Text, _>(realm.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        assert!(
            document_absence_in_connection(
                &mut conn,
                &realm,
                &input.morph_absences[0].1,
                &reader,
                &station(),
                at(3)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn native_morph_document_prior_body_requires_independent_history_permission() {
        let database = morph_database().await;
        let (identity, opening, created, _) = human_document_fixture(&database).await;
        let reader = ActorId::account(identity.history.account.clone());
        let morph = arkret_wire::MorphId::from_event_id(&created.event_id);
        let mut conn = database.pool().get().await.unwrap();
        let patch: arkret_wire::Patch = serde_json::from_value(json!({
            "fields.body":{"$op":"set","value":"Updated body"}
        }))
        .unwrap();
        let payload =
            arkret_models_collaboration::events_payloads::morph::MorphUpdatePayload::for_morph(
                morph.clone(),
                patch,
            )
            .unwrap();
        let update = event(
            EventKind::MorphUpdate,
            &opening.realm_id,
            serde_json::to_value(payload).unwrap(),
            2,
        );
        insert_history(&mut conn, &update, 2).await;
        let output = document_in_connection(
            &mut conn,
            &opening.realm_id,
            &morph,
            &reader,
            &station(),
            at(3),
        )
        .await
        .unwrap()
        .unwrap()
        .0;
        assert_eq!(output.document.body, json!("Updated body"));
        assert!(
            output
                .versions
                .iter()
                .any(|version| version.get("body") == Some(&json!("Body")))
        );
        assert!(
            output
                .versions
                .iter()
                .any(|version| version.get("body") == Some(&json!("Updated body")))
        );
        grant(
            &mut conn,
            &opening,
            &reader,
            &[
                "ak.morph.read",
                "ak.object.read_metadata",
                "ak.object.read_content",
            ],
        )
        .await;
        assert!(
            document_in_connection(
                &mut conn,
                &opening.realm_id,
                &morph,
                &reader,
                &station(),
                at(3)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn native_morph_document_unknown_circle_scope_cannot_be_disclosed_as_realm_body() {
        let database = morph_database().await;
        let reader = actor("ak:did_core:web:morph-reader.example");
        let mut conn = database.pool().get().await.unwrap();
        let opening = seed(&mut conn, &reader).await;
        grant(
            &mut conn,
            &opening,
            &reader,
            &[
                "ak.morph.read",
                "ak.object.read_metadata",
                "ak.object.read_content",
                "ak.object.read_history",
            ],
        )
        .await;
        let mut object = arkret_models_collaboration::objects::profiles::Morph::new(
            arkret_wire::MorphId::from_event_id(&opening.event_id),
            opening.realm_id.clone(),
            "document",
            opening.actor_id.clone(),
        );
        object.id = None;
        object.state = None;
        object.created_at = at(1);
        object.scope_circle_id = Some(arkret_wire::CircleId::from_event_id(&opening.event_id));
        object
            .fields
            .insert("body".into(), json!("Unknown Circle body"));
        let payload =
            arkret_models_collaboration::events_payloads::morph::MorphCreatePayload { object };
        let create = event(
            EventKind::MorphCreate,
            &opening.realm_id,
            serde_json::to_value(payload).unwrap(),
            1,
        );
        insert_history(&mut conn, &create, 1).await;
        let result = document_in_connection(
            &mut conn,
            &opening.realm_id,
            &arkret_wire::MorphId::from_event_id(&create.event_id),
            &reader,
            &station(),
            at(3),
        )
        .await;
        assert!(!matches!(result, Ok(Some(_))));
        assert!(
            document_absence_in_connection(
                &mut conn,
                &opening.realm_id,
                &arkret_wire::MorphId::from_event_id(&create.event_id),
                &reader,
                &station(),
                at(3)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn native_morph_document_controller_full_component_coverage_rejects_omitted_body_or_version()
     {
        let database = morph_database().await;
        let (_, _, _, output) = human_document_fixture(&database).await;
        assert!(owner_covers_document(&output, &output).unwrap());
        let mut owner = output.clone();
        owner.document.body = json!(null);
        assert!(!owner_covers_document(&output, &owner).unwrap());
        assert!(!output.versions.is_empty());
        let mut owner = output.clone();
        owner.versions.clear();
        assert!(!owner_covers_document(&output, &owner).unwrap());
    }

    #[tokio::test]
    async fn native_morph_document_comments_use_exact_accepted_message_and_original_strand_facts() {
        let database = morph_database().await;
        let (identity, opening, created, _) = human_document_fixture(&database).await;
        let reader = ActorId::account(identity.history.account.clone());
        let morph = arkret_wire::MorphId::from_event_id(&created.event_id);
        let mut conn = database.pool().get().await.unwrap();
        let mut object = arkret_models_collaboration::objects::strand::Strand::new_create(
            opening.realm_id.clone(),
            "Document discussion",
            opening.actor_id.clone(),
        );
        object.state = None;
        object.created_at = at(2);
        let strand = event(
            EventKind::StrandCreate,
            &opening.realm_id,
            serde_json::to_value(
                arkret_models_collaboration::events_payloads::strand::StrandCreatePayload {
                    object,
                },
            )
            .unwrap(),
            2,
        );
        insert_history(&mut conn, &strand, 2).await;
        let strand_id = arkret_wire::StrandId::from_event_id(&strand.event_id);
        // The existing product anchor extension is retained inside the original
        // SDK's extensible ContentBlock, not a new Signal/profile or wire DTO.
        let content = arkret_models_collaboration::events_payloads::message::ContentBlock::text(
            "Accepted comment",
        )
        .with_field(
            "anchor_range",
            json!({"target_ref":morph,"start":0,"end":2}),
        );
        let payload: arkret_models_collaboration::events_payloads::message::MessageCreatePayload =
            serde_json::from_value(
                json!({"strand_id":strand_id,"track_name":"discussion","content":content}),
            )
            .unwrap();
        let message = event(
            EventKind::MessageCreate,
            &opening.realm_id,
            serde_json::to_value(payload).unwrap(),
            3,
        );
        insert_history(&mut conn, &message, 3).await;
        let (output, facts) = document_in_connection(
            &mut conn,
            &opening.realm_id,
            &morph,
            &reader,
            &station(),
            at(4),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(output.comments.len(), 1);
        assert_eq!(
            output.comments[0].get("event_id"),
            Some(&json!(message.event_id))
        );
        assert_eq!(
            output.comments[0].get("body"),
            Some(&json!("Accepted comment"))
        );
        assert!(facts.iter().any(|fact| fact.action
            == arkret_wire::CapabilityActionId::ObjectReadHistory
            && fact.facts.strand_id.as_deref() == Some(strand_id.as_str())
            && fact.facts.track.as_deref() == Some("discussion")));
        let mut controller = output.clone();
        controller.comments.clear();
        assert!(!owner_covers_document(&output, &controller).unwrap());
        grant(
            &mut conn,
            &opening,
            &reader,
            &[
                "ak.morph.read",
                "ak.object.read_metadata",
                "ak.object.read_content",
            ],
        )
        .await;
        assert!(
            document_in_connection(
                &mut conn,
                &opening.realm_id,
                &morph,
                &reader,
                &station(),
                at(4)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn native_morph_document_relations_use_exact_original_sdk_endpoints_and_fields() {
        let database = morph_database().await;
        let (identity, opening, created, _) = human_document_fixture(&database).await;
        let reader = ActorId::account(identity.history.account.clone());
        let morph = arkret_wire::MorphId::from_event_id(&created.event_id);
        let mut conn = database.pool().get().await.unwrap();
        let mut next: arkret_models_collaboration::events_payloads::morph::MorphCreatePayload =
            serde_json::from_value(serde_json::to_value(&created.payload).unwrap()).unwrap();
        next.object = next.object.with_metadata_title("Related document");
        next.object.created_at = at(2);
        let second = event(
            EventKind::MorphCreate,
            &opening.realm_id,
            serde_json::to_value(next).unwrap(),
            2,
        );
        insert_history(&mut conn, &second, 2).await;
        let endpoint = arkret_wire::MorphId::from_event_id(&second.event_id);
        let definition: arkret_wire::relation::RelationDefinition = serde_json::from_value(json!({
            "relation_kind":"references","from_ref":morph,"to_ref":endpoint,"fields":{"label":"Original reference"}
        })).unwrap();
        let domain = arkret_wire::relation::RelationPrimaryConflictDomain::try_new(
            arkret_wire::relation::RelationPrimaryConflictDomainKind::Tuple,
            definition.relation_kind.clone(),
            definition.from_ref.clone(),
            Some(definition.to_ref.clone()),
        )
        .unwrap();
        let payload =
            arkret_models_collaboration::events_payloads::relation::RelationCreatePayload::try_new(
                domain, None, definition,
            )
            .unwrap();
        let relation = event(
            EventKind::RelationCreate,
            &opening.realm_id,
            payload.to_value().unwrap(),
            3,
        );
        insert_history(&mut conn, &relation, 3).await;
        let output = document_in_connection(
            &mut conn,
            &opening.realm_id,
            &morph,
            &reader,
            &station(),
            at(4),
        )
        .await
        .unwrap()
        .unwrap()
        .0;
        assert_eq!(output.relations.len(), 1);
        assert_eq!(
            output.relations[0].get("relation_id"),
            Some(&json!(arkret_wire::RelationId::from_event_id(
                &relation.event_id
            )))
        );
        assert_eq!(
            output.relations[0].get("fields"),
            Some(&json!({"label":"Original reference"}))
        );
        assert_eq!(
            output.relations[0].get("reference_projection"),
            Some(&json!({"status":"accessible"}))
        );
        let mut owner = output.clone();
        owner.relations[0].insert("fields".into(), json!({"label":"Substituted reference"}));
        assert!(!owner_covers_document(&output, &owner).unwrap());
    }

    #[tokio::test]
    async fn native_morph_cold_source_uses_original_mapping_and_commit_successor() {
        let database = morph_database().await;
        let mut conn = database.pool().get().await.unwrap();
        let reader = actor("ak:did_core:web:morph-reader.example");
        let opening = seed(&mut conn, &reader).await;
        let create = create_morph(&mut conn, &opening.realm_id).await;
        let id = arkret_wire::MorphId::from_event_id(&create.event_id);
        let update = event(
            EventKind::MorphUpdate,
            &opening.realm_id,
            json!({"target_ref":id,"patch":{"metadata.title":{"$op":"set","value":"Accepted successor"}}}),
            2,
        );
        insert_history(&mut conn, &update, 2).await;
        drop(conn);
        let mut cold = database.pool().get().await.unwrap();
        let material = material_in_connection(&mut cold, &opening.realm_id, &station())
            .await
            .unwrap();
        assert_eq!(
            material.state.morphs[id.as_str()].title.as_deref(),
            Some("Accepted successor")
        );
        assert_eq!(material.originals.len(), 5);
        assert_eq!(material.heads[0].stream_position, 4);
    }

    #[tokio::test]
    async fn native_morph_mapping_payload_substitution_is_not_projection_authority() {
        let database = morph_database().await;
        let mut conn = database.pool().get().await.unwrap();
        let opening = seed(&mut conn, &actor("ak:did_core:web:morph-reader.example")).await;
        create_morph(&mut conn, &opening.realm_id).await;
        sql_query("UPDATE projection_events SET payload=jsonb_set(payload,'{object,metadata,title}','\"Substituted\"') WHERE event_kind='ak.morph.create'")
            .execute(&mut *conn).await.unwrap();
        let error = material_in_connection(&mut conn, &opening.realm_id, &station())
            .await
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("differs from accepted producer content")
        );
    }

    #[tokio::test]
    async fn native_morph_missing_mapping_and_broken_commit_chain_are_unavailable() {
        let database = morph_database().await;
        let mut conn = database.pool().get().await.unwrap();
        let opening = seed(&mut conn, &actor("ak:did_core:web:morph-reader.example")).await;
        create_morph(&mut conn, &opening.realm_id).await;
        sql_query("DELETE FROM projection_events WHERE event_kind='ak.morph.create'")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert!(
            material_in_connection(&mut conn, &opening.realm_id, &station())
                .await
                .is_err()
        );
        sql_query("UPDATE realm_commits SET commit_json=jsonb_set(commit_json,'{previous_commit_ref}',to_jsonb($1::text)) WHERE stream_position=3")
            .bind::<Text,_>(arkret_wire::RealmCommitId::from_digest([99;32]).as_str())
            .execute(&mut *conn).await.unwrap();
        assert!(
            material_in_connection(&mut conn, &opening.realm_id, &station())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn native_morph_replica_without_governing_barrier_is_unavailable() {
        let database = morph_database().await;
        let mut conn = database.pool().get().await.unwrap();
        let opening = seed(&mut conn, &actor("ak:did_core:web:morph-reader.example")).await;
        let replica = "ak:did_core:web:replica.example".parse().unwrap();
        assert!(
            material_in_connection(&mut conn, &opening.realm_id, &replica)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn native_morph_list_requires_literal_read_and_independent_metadata() {
        let database = morph_database().await;
        let mut conn = database.pool().get().await.unwrap();
        let reader = actor("ak:did_core:web:morph-reader.example");
        let opening = seed(&mut conn, &reader).await;
        create_morph(&mut conn, &opening.realm_id).await;
        assert!(
            list_in_connection(
                &mut conn,
                &opening.realm_id,
                &reader,
                &station(),
                false,
                at(3)
            )
            .await
            .is_err()
        );
        grant(&mut conn, &opening, &reader, &["ak.morph.read"]).await;
        assert!(
            list_in_connection(
                &mut conn,
                &opening.realm_id,
                &reader,
                &station(),
                false,
                at(3)
            )
            .await
            .is_err()
        );
        grant(
            &mut conn,
            &opening,
            &reader,
            &["ak.morph.read", "ak.object.read_metadata"],
        )
        .await;
        let (list, facts) = list_in_connection(
            &mut conn,
            &opening.realm_id,
            &reader,
            &station(),
            false,
            at(3),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(list.total, 1);
        assert_eq!(facts.len(), 2);
        sql_query("UPDATE member_state_current_results SET membership='leave',value=jsonb_set(value,'{membership}','\"leave\"'::jsonb)")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert!(
            list_in_connection(
                &mut conn,
                &opening.realm_id,
                &reader,
                &station(),
                false,
                at(3)
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    #[tokio::test]
    async fn native_morph_empty_list_and_absent_document_require_complete_read_proof() {
        let database = morph_database().await;
        let mut conn = database.pool().get().await.unwrap();
        let reader = actor("ak:did_core:web:morph-reader.example");
        let opening = seed(&mut conn, &reader).await;
        assert!(
            list_in_connection(
                &mut conn,
                &opening.realm_id,
                &reader,
                &station(),
                false,
                at(3)
            )
            .await
            .is_err()
        );
        grant(
            &mut conn,
            &opening,
            &reader,
            &["ak.morph.read", "ak.object.read_metadata"],
        )
        .await;
        let (list, facts) = list_in_connection(
            &mut conn,
            &opening.realm_id,
            &reader,
            &station(),
            false,
            at(3),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(list.morphs.is_empty());
        assert_eq!(facts.len(), 2);
        let id = arkret_wire::MorphId::from_event_id(&opening.event_id);
        assert!(
            document_in_connection(
                &mut conn,
                &opening.realm_id,
                &id,
                &reader,
                &station(),
                at(3)
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    async fn constraints(conn: &mut AsyncPgConnection, value: serde_json::Value) {
        sql_query(
            "UPDATE capability_grant_current_results SET value=jsonb_set(value,'{constraints}',$1)",
        )
        .bind::<Jsonb, _>(value)
        .execute(&mut *conn)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn native_morph_read_quota_has_no_registered_identity_and_never_reserves() {
        use arkret_models_collaboration::governance::grant_constraint::{
            GrantConstraint, GrantConstraintEffect, GrantConstraintKind, GrantConstraintScope,
            GrantConstraintSubkind,
        };
        let database = morph_database().await;
        let mut conn = database.pool().get().await.unwrap();
        let reader = actor("ak:did_core:web:morph-reader.example");
        let opening = seed(&mut conn, &reader).await;
        create_morph(&mut conn, &opening.realm_id).await;
        grant(
            &mut conn,
            &opening,
            &reader,
            &["ak.morph.read", "ak.object.read_metadata"],
        )
        .await;
        let mut quota =
            GrantConstraint::new(GrantConstraintKind::Quota, GrantConstraintEffect::Allow);
        quota.constraint_subkind = Some(GrantConstraintSubkind::Rate);
        quota.max_operations = Some(3);
        quota.period = Some("PT1H".to_owned());
        quota.constraint_scope = Some(GrantConstraintScope::PerRealm);
        constraints(&mut conn, json!([quota])).await;
        assert!(
            list_in_connection(
                &mut conn,
                &opening.realm_id,
                &reader,
                &station(),
                false,
                at(3)
            )
            .await
            .is_err()
        );
        #[derive(QueryableByName)]
        struct QuotaCount {
            #[diesel(sql_type = BigInt)]
            count: i64,
        }
        let quota_count = sql_query("SELECT ((SELECT count(*) FROM capability_quota_consumptions) + (SELECT count(*) FROM capability_quota_counters) + (SELECT count(*) FROM capability_quota_buckets))::bigint AS count")
            .get_result::<QuotaCount>(&mut *conn).await.unwrap();
        assert_eq!(
            quota_count.count, 0,
            "read refusal cannot consume an invented quota identity"
        );
        constraints(&mut conn, json!([])).await;
        assert!(
            list_in_connection(
                &mut conn,
                &opening.realm_id,
                &reader,
                &station(),
                false,
                at(3)
            )
            .await
            .unwrap()
            .is_some()
        );
    }

    #[tokio::test]
    async fn native_morph_global_read_field_refusal_and_unknown_data_label_fail_closed() {
        use arkret_models_collaboration::governance::grant_constraint::{
            GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
        };
        let database = morph_database().await;
        let mut conn = database.pool().get().await.unwrap();
        let reader = actor("ak:did_core:web:morph-reader.example");
        let opening = seed(&mut conn, &reader).await;
        create_morph(&mut conn, &opening.realm_id).await;
        grant(
            &mut conn,
            &opening,
            &reader,
            &["ak.morph.read", "ak.object.read_metadata"],
        )
        .await;
        let mut deny = GrantConstraint::new(
            GrantConstraintKind::FieldAccess,
            GrantConstraintEffect::Deny,
        );
        deny.denied_read_fields = vec!["title".to_owned()];
        constraints(&mut conn, json!([deny])).await;
        assert!(
            list_in_connection(
                &mut conn,
                &opening.realm_id,
                &reader,
                &station(),
                false,
                at(3)
            )
            .await
            .is_err()
        );
        let mut label = GrantConstraint::new(
            GrantConstraintKind::ScopeLimitation,
            GrantConstraintEffect::Allow,
        );
        label.allowed_data_labels = vec!["public".to_owned()];
        constraints(&mut conn, json!([label])).await;
        assert!(
            list_in_connection(
                &mut conn,
                &opening.realm_id,
                &reader,
                &station(),
                false,
                at(3)
            )
            .await
            .is_err()
        );
        constraints(&mut conn, json!([])).await;
        assert!(
            list_in_connection(
                &mut conn,
                &opening.realm_id,
                &reader,
                &station(),
                false,
                at(3)
            )
            .await
            .unwrap()
            .is_some()
        );
    }

    #[tokio::test]
    async fn native_morph_unknown_identity_cannot_take_ordinary_human_handoff() {
        let database = morph_database().await;
        let mut conn = database.pool().get().await.unwrap();
        let reader = actor("ak:did_core:web:morph-reader.example");
        let opening = seed(&mut conn, &reader).await;
        grant(
            &mut conn,
            &opening,
            &reader,
            &["ak.morph.read", "ak.object.read_metadata"],
        )
        .await;
        let (list, _) = list_in_connection(
            &mut conn,
            &opening.realm_id,
            &reader,
            &station(),
            false,
            at(3),
        )
        .await
        .unwrap()
        .unwrap();
        drop(conn);
        let input = coland_storage::AccountContentDeliveryInput {
            morph_lists: vec![(opening.realm_id, false, list)],
            ..Default::default()
        };
        assert!(
            fixture_delivery_guard(
                &database.pool(),
                reader.as_account_id().unwrap(),
                &station(),
                &input
            )
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("accepted human registration anchor")
        );
    }

    #[tokio::test]
    async fn native_morph_accepted_human_list_holds_cut_and_rechecks_empty_substitution() {
        let database = morph_database().await;
        let persistence = crate::PgPersistenceStore::new(database.pool().clone());
        let identity = super::pcr_genesis::PcrGenesisFixture::new(
            "did:web:morph-station.example".parse().unwrap(),
        );
        identity.admit_into(&persistence).await.unwrap();
        import_human_status_genesis(&database.pool(), &persistence, &identity).await;
        let reader = ActorId::account(identity.history.account.clone());
        let mut conn = database.pool().get().await.unwrap();
        let opening = seed(&mut conn, &reader).await;
        grant(
            &mut conn,
            &opening,
            &reader,
            &["ak.morph.read", "ak.object.read_metadata"],
        )
        .await;
        let (list, _) = list_in_connection(
            &mut conn,
            &opening.realm_id,
            &reader,
            &station(),
            false,
            at(3),
        )
        .await
        .unwrap()
        .unwrap();
        drop(conn);
        let input = coland_storage::AccountContentDeliveryInput {
            morph_lists: vec![(opening.realm_id.clone(), false, list.clone())],
            ..Default::default()
        };
        let guard = fixture_delivery_guard(
            &database.pool(),
            reader.as_account_id().unwrap(),
            &station(),
            &input,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(guard.permits_handoff());
        let pool = database.pool();
        let realm = opening.realm_id.clone();
        let blocked = tokio::spawn(async move {
            let mut conn = pool.get().await.unwrap();
            sql_query("BEGIN").execute(&mut *conn).await.unwrap();
            sql_query("SET LOCAL lock_timeout='75ms'")
                .execute(&mut *conn)
                .await
                .unwrap();
            assert!(
                crate::realm_authorization_cut::lock_realm_authorization_cut(&mut conn, &realm)
                    .await
                    .is_err()
            );
            sql_query("ROLLBACK").execute(&mut *conn).await.unwrap();
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), blocked)
            .await
            .unwrap()
            .unwrap();
        assert!(guard.permits_handoff());
        guard.finish().await.unwrap();
        let mut conn = database.pool().get().await.unwrap();
        sql_query("BEGIN").execute(&mut *conn).await.unwrap();
        crate::realm_authorization_cut::lock_realm_authorization_cut(&mut conn, &opening.realm_id)
            .await
            .unwrap();
        sql_query("UPDATE member_state_current_results SET membership='leave',value=jsonb_set(value,'{membership}','\"leave\"'::jsonb) WHERE realm_id=$1")
            .bind::<Text, _>(opening.realm_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        sql_query("COMMIT").execute(&mut *conn).await.unwrap();
        drop(conn);
        assert!(
            fixture_delivery_guard(
                &database.pool(),
                reader.as_account_id().unwrap(),
                &station(),
                &input
            )
            .await
            .is_err()
        );
        let mut conn = database.pool().get().await.unwrap();
        sql_query("UPDATE member_state_current_results SET membership='join',value=jsonb_set(value,'{membership}','\"join\"'::jsonb) WHERE realm_id=$1")
            .bind::<Text, _>(opening.realm_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        create_morph(&mut conn, &opening.realm_id).await;
        drop(conn);
        assert!(
            fixture_delivery_guard(
                &database.pool(),
                reader.as_account_id().unwrap(),
                &station(),
                &input
            )
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("changed, including empty list")
        );
    }
    #[tokio::test]
    async fn native_morph_missing_tail_commit_cannot_prove_empty_absence() {
        let database = morph_database().await;
        let mut conn = database.pool().get().await.unwrap();
        let opening = seed(&mut conn, &actor("ak:did_core:web:morph-reader.example")).await;
        create_morph(&mut conn, &opening.realm_id).await;
        sql_query("DELETE FROM realm_commits WHERE realm_id=$1 AND stream_position=3")
            .bind::<Text, _>(opening.realm_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        let error = material_in_connection(&mut conn, &opening.realm_id, &station())
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("no retained covering Commit"));
    }

    #[tokio::test]
    async fn native_morph_registered_current_newer_than_retained_tail_is_unavailable() {
        let database = morph_database().await;
        let mut conn = database.pool().get().await.unwrap();
        let opening = seed(&mut conn, &actor("ak:did_core:web:morph-reader.example")).await;
        let tail = create_morph(&mut conn, &opening.realm_id).await;
        // The original registered current port retains its accepted exact
        // source. A truncated history must not reinterpret it as absent.
        sql_query("UPDATE member_state_current_results SET current_commit_id=$2,current_stream_position=3 WHERE realm_id=$1")
            .bind::<Text,_>(opening.realm_id.as_str()).bind::<Text,_>(commit(&tail,1).commit_id.as_str())
            .execute(&mut *conn).await.unwrap();
        sql_query("DELETE FROM realm_commits WHERE realm_id=$1 AND stream_position=3")
            .bind::<Text, _>(opening.realm_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        let error = material_in_connection(&mut conn, &opening.realm_id, &station())
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("current source is outside"));
    }

    #[tokio::test]
    async fn native_morph_valid_prefix_must_equal_original_held_head_set() {
        let database = morph_database().await;
        let mut conn = database.pool().get().await.unwrap();
        let opening = seed(&mut conn, &actor("ak:did_core:web:morph-reader.example")).await;
        create_morph(&mut conn, &opening.realm_id).await;
        let full = crate::committed_disclosure::accepted_full_event_in_connection(
            &mut conn,
            &opening.event_id,
        )
        .await
        .unwrap()
        .unwrap();
        let mut prefix = CommitStreamProjection::new();
        prefix.apply_committed(full.clone()).unwrap();
        let originals = BTreeMap::from([(full.event.event_id.clone(), full)]);
        let error =
            require_complete_held_sources(&mut conn, &opening.realm_id, &prefix, &originals)
                .await
                .unwrap_err();
        assert!(error.to_string().contains("held governing head set"));
    }

    async fn human_list_fixture(
        database: &crate::test_database::TestDatabase,
    ) -> (
        crate::PgPersistenceStore,
        super::pcr_genesis::PcrGenesisFixture,
        coland_storage::AccountContentDeliveryInput,
    ) {
        let persistence = crate::PgPersistenceStore::new(database.pool());
        let identity = super::pcr_genesis::PcrGenesisFixture::new(
            "did:web:morph-station.example".parse().unwrap(),
        );
        identity.admit_into(&persistence).await.unwrap();
        import_human_status_genesis(&database.pool(), &persistence, &identity).await;
        let reader = ActorId::account(identity.history.account.clone());
        let mut conn = database.pool().get().await.unwrap();
        let opening = seed(&mut conn, &reader).await;
        grant(
            &mut conn,
            &opening,
            &reader,
            &["ak.morph.read", "ak.object.read_metadata"],
        )
        .await;
        let (list, _) = list_in_connection(
            &mut conn,
            &opening.realm_id,
            &reader,
            &station(),
            false,
            at(3),
        )
        .await
        .unwrap()
        .unwrap();
        (
            persistence,
            identity,
            coland_storage::AccountContentDeliveryInput {
                morph_lists: vec![(opening.realm_id, false, list)],
                ..Default::default()
            },
        )
    }

    #[tokio::test]
    async fn native_morph_accepted_human_terminal_pcr_cannot_reuse_genesis() {
        let database = morph_database().await;
        let (_, identity, input) = human_list_fixture(&database).await;
        let account = &identity.history.account;
        let mut conn = database.pool().get().await.unwrap();
        let pcr = human_realm_in_connection(&mut conn, account).await.unwrap();
        let tail = sql_query("SELECT commit_json FROM realm_commits WHERE realm_id=$1 ORDER BY stream_position DESC LIMIT 1")
            .bind::<Text,_>(pcr.as_str()).get_result::<PcrCommitRow>(&mut *conn).await.unwrap();
        let tail: RealmCommit = serde_json::from_value(tail.commit_json).unwrap();
        let next = tail.stream_position + 1;
        let payload =
            arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload::new(
                pcr.clone(),
                "Imported accepted terminal boundary",
            )
            .to_value()
            .unwrap();
        let terminal = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::RealmTombstone.as_str(),
            ScopeRef::Realm {
                realm_id: pcr.clone(),
            },
            ActorId::account(account.clone()),
            payload,
            at(next),
        )
        .unwrap();
        insert_history(&mut conn, &terminal, next).await;
        sql_query("UPDATE realm_commits SET previous_commit_ref=$2,commit_json=jsonb_set(commit_json,'{previous_commit_ref}',to_jsonb($2::text)) WHERE commit_id=$1")
            .bind::<Text,_>(commit(&terminal,next).commit_id.as_str()).bind::<Text,_>(tail.commit_id.as_str())
            .execute(&mut *conn).await.unwrap();
        drop(conn);
        let error = fixture_delivery_guard(&database.pool(), account, &station(), &input)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("human PCR current is terminal"));
    }

    #[tokio::test]
    async fn native_morph_human_lifecycle_writer_waits_for_actual_handoff() {
        let database = morph_database().await;
        let (persistence, identity, input) = human_list_fixture(&database).await;
        let account = identity.history.account;
        let mut conn = database.pool().get().await.unwrap();
        sql_query("INSERT INTO accounts(principal_id,station_id,payload) VALUES($1,$2,'{}')")
            .bind::<Text, _>(account.principal_id.as_str())
            .bind::<Text, _>(account.station_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        let pk = persistence
            .accounts()
            .get(&account)
            .await
            .unwrap()
            .unwrap()
            .pk;
        let guard = fixture_delivery_guard(&database.pool(), &account, &station(), &input)
            .await
            .unwrap()
            .unwrap();
        assert!(guard.permits_handoff());
        let pool = database.pool();
        let (started, ready) = tokio::sync::oneshot::channel();
        let mut writer = tokio::spawn(async move {
            let persistence = crate::PgPersistenceStore::new(pool);
            started.send(()).unwrap();
            persistence
                .account_lifecycle()
                .put(
                    pk,
                    &coland_storage::AccountLifecycleRecord {
                        state: "deactivated".to_owned(),
                        reason: None,
                        changed_by: None,
                        changed_at: chrono::Utc::now(),
                    },
                )
                .await
        });
        ready.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut writer)
                .await
                .is_err()
        );
        assert!(guard.permits_handoff());
        guard.finish().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), writer)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let error = fixture_delivery_guard(&database.pool(), &account, &station(), &input)
            .await
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("Account lifecycle is not active")
        );
    }

    async fn import_human_status_genesis(
        pool: &crate::PgPool,
        persistence: &crate::PgPersistenceStore,
        identity: &super::pcr_genesis::PcrGenesisFixture,
    ) {
        let mut conn = pool.get().await.unwrap();
        let pcr = human_realm_in_connection(&mut conn, &identity.history.account)
            .await
            .unwrap();
        drop(conn);
        let (record, receipt) = signed_status(&identity.history.account, &pcr, None);
        assert!(matches!(
            persistence
                .account_status_replicas()
                .append(&record, &receipt)
                .await
                .unwrap(),
            coland_storage::AccountStatusReplicaAppend::Accepted(_)
        ));
    }

    fn signed_status(
        account: &arkret_wire::AccountId,
        pcr: &RealmId,
        previous: Option<&arkret_models_collaboration::account_status::AccountStatusRecord>,
    ) -> (
        arkret_models_collaboration::account_status::AccountStatusRecord,
        arkret_models_collaboration::account_status::AccountStatusReceipt,
    ) {
        use arkret_models_collaboration::account_status::{
            UnsignedAccountStatusReceipt, UnsignedAccountStatusRecord,
        };
        use arkret_models_collaboration::objects::account_status::AccountStatus;
        use arkret_signatures::account_status::{
            sign_account_status_receipt, sign_account_status_record,
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[94; 32]);
        let method = arkret_wire::DidUrl::new("did:web:morph-station.example#status").unwrap();
        let record = sign_account_status_record(
            UnsignedAccountStatusRecord {
                schema: arkret_wire::SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
                account_authority_id: account.station_id.clone(),
                account_id: account.clone(),
                principal_control_realm_id: pcr.clone(),
                binding_version: 1,
                status_seq: previous.map_or(1, |record| record.status_seq + 1),
                previous_account_status_record_id: previous
                    .map(|record| record.account_status_record_id.clone()),
                status: if previous.is_some() {
                    AccountStatus::Deactivated
                } else {
                    AccountStatus::Active
                },
                reason_code: None,
                reason: None,
                issued_at: chrono::Utc::now(),
                expires_at: None,
            },
            method.clone(),
            &key,
        )
        .unwrap();
        let receipt = sign_account_status_receipt(
            UnsignedAccountStatusReceipt {
                receipt_id: arkret_wire::ReceiptId::new(crate::ids::format_typed_uuid(
                    "receipt",
                    &uuid::Uuid::now_v7(),
                ))
                .unwrap(),
                account_status_record_id: record.account_status_record_id.clone(),
                record_digest: record.payload_digest().unwrap(),
                account_authority_id: account.station_id.clone(),
                account_id: account.clone(),
                status_seq: record.status_seq,
                receiver_id: station(),
                accepted_at: chrono::Utc::now(),
                verification_method: method,
            },
            &key,
        )
        .unwrap();
        (record, receipt)
    }

    #[tokio::test]
    async fn native_morph_typed_status_binding_distinguishes_verified_terminal_from_missing() {
        use arkret_models_collaboration::objects::account_status::AccountStatus;
        let database = morph_database().await;
        let (persistence, identity, _) = human_list_fixture(&database).await;
        let account = &identity.history.account;
        let mut conn = database.pool().get().await.unwrap();
        let pcr = human_realm_in_connection(&mut conn, account).await.unwrap();
        drop(conn);
        let initial = persistence
            .account_status_replicas()
            .current(account.station_id.as_str(), account)
            .await
            .unwrap()
            .unwrap();
        let (terminal, receipt) = signed_status(account, &pcr, Some(&initial));
        // Resolve decodes the original signed wire before binding its exact head.
        let terminal_bytes = arkret_canonical::canonical_json_bytes(&terminal).unwrap();
        let terminal: arkret_models_collaboration::account_status::AccountStatusRecord =
            serde_json::from_slice(&terminal_bytes).unwrap();
        assert!(arkret_canonical::canonical_json_bytes(&terminal).unwrap() == terminal_bytes);
        assert!(matches!(
            persistence
                .account_status_replicas()
                .append(&terminal, &receipt)
                .await
                .unwrap(),
            coland_storage::AccountStatusReplicaAppend::Accepted(_)
        ));
        let stored = persistence
            .account_status_replicas()
            .current(account.station_id.as_str(), account)
            .await
            .unwrap()
            .unwrap();
        assert!(stored == terminal);
        let observation =
            coland_storage::AccountStatusCurrentObservation::after_authenticated_resolve(terminal);
        let mut conn = database.pool().get().await.unwrap();
        require_accepted_human_pcr_in_connection(&mut conn, account, &pcr)
            .await
            .unwrap();
        assert_eq!(
            require_observed_account_status_binding_in_connection(
                &mut conn,
                account,
                &pcr,
                &station(),
                Some(&observation),
            )
            .await
            .unwrap(),
            AccountStatus::Deactivated,
        );
        let error = require_observed_account_status_in_connection(
            &mut conn,
            account,
            &pcr,
            &station(),
            Some(&observation),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("Account status is not active"));
        let error = require_observed_account_status_binding_in_connection(
            &mut conn,
            account,
            &pcr,
            &station(),
            None,
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("current observation is unavailable")
        );
        let stale =
            coland_storage::AccountStatusCurrentObservation::after_authenticated_resolve(initial);
        let error = require_observed_account_status_binding_in_connection(
            &mut conn,
            account,
            &pcr,
            &station(),
            Some(&stale),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("head changed after current resolve")
        );
    }

    #[tokio::test]
    async fn native_morph_pcr_only_qualification_preserves_missing_aa_evidence_failure() {
        let database = morph_database().await;
        let (_, identity, _) = human_list_fixture(&database).await;
        let account = &identity.history.account;
        let mut conn = database.pool().get().await.unwrap();
        let pcr = human_realm_in_connection(&mut conn, account).await.unwrap();
        sql_query("DELETE FROM account_status_replica_records WHERE account_id=$1")
            .bind::<Jsonb, _>(json!(account))
            .execute(&mut *conn)
            .await
            .unwrap();
        require_accepted_human_pcr_in_connection(&mut conn, account, &pcr)
            .await
            .unwrap();
        let error = require_observed_account_status_binding_in_connection(
            &mut conn,
            account,
            &pcr,
            &station(),
            None,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("lifecycle head is unavailable"));
        let error = require_accepted_human_identity(&mut conn, account, &pcr, &station(), None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("lifecycle head is unavailable"));
    }

    #[tokio::test]
    async fn native_morph_pcr_identity_cannot_replace_missing_authority_lifecycle_head() {
        let database = morph_database().await;
        let (_, identity, input) = human_list_fixture(&database).await;
        let mut conn = database.pool().get().await.unwrap();
        sql_query("DELETE FROM account_status_replica_records WHERE account_id=$1")
            .bind::<Jsonb, _>(json!(identity.history.account))
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        let error = fixture_delivery_guard(
            &database.pool(),
            &identity.history.account,
            &station(),
            &input,
        )
        .await
        .err()
        .unwrap();
        assert!(error.to_string().contains("lifecycle head is unavailable"));
    }

    #[tokio::test]
    async fn native_morph_human_signed_status_successor_waits_and_refuses_after_handoff() {
        let database = morph_database().await;
        let (persistence, identity, input) = human_list_fixture(&database).await;
        let account = identity.history.account;
        let mut conn = database.pool().get().await.unwrap();
        let pcr = human_realm_in_connection(&mut conn, &account)
            .await
            .unwrap();
        drop(conn);
        let initial = persistence
            .account_status_replicas()
            .current(account.station_id.as_str(), &account)
            .await
            .unwrap()
            .unwrap();
        let guard = fixture_delivery_guard(&database.pool(), &account, &station(), &input)
            .await
            .unwrap()
            .unwrap();
        let (next, receipt) = signed_status(&account, &pcr, Some(&initial));
        let pool = database.pool();
        let (started, ready) = tokio::sync::oneshot::channel();
        let mut writer = tokio::spawn(async move {
            let persistence = crate::PgPersistenceStore::new(pool);
            started.send(()).unwrap();
            persistence
                .account_status_replicas()
                .append(&next, &receipt)
                .await
        });
        ready.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut writer)
                .await
                .is_err()
        );
        assert!(guard.permits_handoff());
        guard.finish().await.unwrap();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(5), writer)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            coland_storage::AccountStatusReplicaAppend::Accepted(_)
        ));
        let error = fixture_delivery_guard(&database.pool(), &account, &station(), &input)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("Account status is not active"));
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_morph_non_morph_delivery_uses_default_worker_stack() {
        let database = morph_database().await;
        let (_, identity, mut input) = human_list_fixture(&database).await;
        input.realms = vec![input.morph_lists[0].0.clone()];
        input.morph_lists.clear();
        let pool = database.pool();
        let account = identity.history.account;
        let guard = tokio::spawn(async move {
            crate::account_content_delivery::acquire(&pool, &account, &station(), &input).await
        })
        .await
        .unwrap()
        .unwrap();
        assert!(guard.is_none());
    }

    #[tokio::test]
    async fn native_morph_verified_history_without_current_observation_is_unavailable() {
        let database = morph_database().await;
        let (_, identity, input) = human_list_fixture(&database).await;
        let error = ordinary_delivery_guard(
            &database.pool(),
            &identity.history.account,
            &station(),
            &input,
        )
        .await
        .err()
        .unwrap();
        assert!(
            error
                .to_string()
                .contains("current observation is unavailable")
        );
    }

    #[tokio::test]
    async fn native_morph_successor_between_resolve_and_cut_rejects_old_observation() {
        let database = morph_database().await;
        let (persistence, identity, mut input) = human_list_fixture(&database).await;
        let account = identity.history.account;
        let initial = persistence
            .account_status_replicas()
            .current(account.station_id.as_str(), &account)
            .await
            .unwrap()
            .unwrap();
        input.account_status_observations = vec![
            coland_storage::AccountStatusCurrentObservation::after_authenticated_resolve(
                initial.clone(),
            ),
        ];
        let mut conn = database.pool().get().await.unwrap();
        let pcr = human_realm_in_connection(&mut conn, &account)
            .await
            .unwrap();
        drop(conn);
        let (next, receipt) = signed_status(&account, &pcr, Some(&initial));
        assert!(matches!(
            persistence
                .account_status_replicas()
                .append(&next, &receipt)
                .await
                .unwrap(),
            coland_storage::AccountStatusReplicaAppend::Accepted(_)
        ));
        let error = ordinary_delivery_guard(&database.pool(), &account, &station(), &input)
            .await
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("head changed after current resolve")
        );
    }
}
