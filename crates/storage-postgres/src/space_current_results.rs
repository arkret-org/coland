//! The three registered `ak.space.create` results at one RealmCommit cut,
//! and the `ak.space.archive` / `ak.space.restore` lifecycle successor of the
//! `space` family.
//!
//! `space` is metadata only. The structural parent and child scope policy have
//! their own current families; an absent signed member becomes an explicit
//! genesis `null` in those families. These writers run inside the
//! Event/Commit transaction, while the caller holds the Realm authority row
//! lock.

use coland_storage::{PersistenceError, PersistenceResult};
use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

#[derive(diesel::QueryableByName)]
struct ParentCurrentRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
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

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    present: bool,
}

#[derive(diesel::QueryableByName)]
struct SpaceCurrentRow {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

pub(crate) struct SpaceCreateValues {
    pub(crate) space_id: arkret_wire::SpaceId,
    pub(crate) space: Value,
    pub(crate) parent: Value,
    pub(crate) child_scope_policy: Value,
}

fn reject(detail: impl Into<String>) -> PersistenceError {
    let detail = detail.into();
    let code = match detail.as_str() {
        "space_parent_mismatch" => Some(coland_storage::ConflictCode::SpaceParentMismatch),
        "space_parent_unreadable" => Some(coland_storage::ConflictCode::SpaceParentUnreadable),
        "space_realm_mismatch" => Some(coland_storage::ConflictCode::SpaceRealmMismatch),
        _ => None,
    };
    match code {
        Some(code) => reject_lifecycle(code, &detail),
        None => PersistenceError::Conflict(format!("failed_precondition: {detail}")),
    }
}

fn reject_lifecycle(code: coland_storage::ConflictCode, detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", code.as_str()))
}

/// Derive the three registry results from the signed Event, without trusting
/// a payload-provided object id, parent in metadata, or synthesized policy.
pub(crate) fn space_create_current_values(
    event: &arkret_wire::Event,
) -> PersistenceResult<SpaceCreateValues> {
    if event.kind != arkret_wire::EventKind::SpaceCreate {
        return Err(PersistenceError::SchemaViolation(
            "expected ak.space.create".to_owned(),
        ));
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let payload: arkret_models_collaboration::events_payloads::space::SpaceCreatePayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let object = payload.object;
    object
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if object.id.is_some()
        || object.realm_id != event.realm_id
        || object.created_by != event.actor_id
        || object.created_at != event.created_at
        || object
            .state
            .as_ref()
            .is_some_and(|state| state != &arkret_wire::SpaceState::Active)
        || object.state_changed_at.is_some()
        || object.updated_by.is_some()
        || object.updated_at.is_some()
        || object.schema != arkret_models_collaboration::objects::space::Space::SCHEMA
    {
        return Err(PersistenceError::SchemaViolation(
            "Space create contains a forged or non-initial derived member".to_owned(),
        ));
    }
    let space_id = arkret_wire::SpaceId::from_event_id(&event.event_id);
    if object.parent_space_id.as_ref() == Some(&space_id) {
        return Err(reject("space_parent_cycle"));
    }
    if matches!(
        object.child_scope_policy.as_ref(),
        Some(
            arkret_models_collaboration::objects::space::ChildScopePolicy::RequireScopeCircleId { .. }
        )
    ) {
        return Err(reject(
            "Circle-targeting child policy needs a confirmed Circle authority cut",
        ));
    }
    let parent = json!({"parent_space_id": object.parent_space_id.as_ref()});
    let child_scope_policy =
        serde_json::to_value(&object.child_scope_policy).map_err(PersistenceError::database)?;
    let mut space = serde_json::to_value(&object).map_err(PersistenceError::database)?;
    let members = space.as_object_mut().ok_or_else(|| {
        PersistenceError::SchemaViolation("Space create object is not an object".to_owned())
    })?;
    members.remove("parent_space_id");
    members.remove("child_scope_policy");
    members.insert("id".to_owned(), json!(space_id));
    members.insert("state".to_owned(), json!("active"));
    Ok(SpaceCreateValues {
        space_id,
        space,
        parent,
        child_scope_policy,
    })
}

/// Prove the parent from complete same-Realm current rows. The standalone
/// Realm-scope slice refuses Circle-scoped metadata until a Circle authority
/// cut supplies its scope/readability proof. It also refuses a missing or
/// mismatched sibling family rather than treating it as a root or allow-any.
async fn require_parent_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    position: i64,
    values: &SpaceCreateValues,
) -> PersistenceResult<()> {
    if values.space.get("scope_circle_id").is_some() {
        return Err(reject("Circle-scoped Space needs a Circle authority cut"));
    }
    let Some(parent_id) = values.parent["parent_space_id"].as_str() else {
        return Ok(());
    };
    let parent = diesel::sql_query(
        "SELECT s.realm_id,s.value AS space,\
                p.current_commit_id AS parent_commit_id,\
                p.current_stream_position AS parent_position,p.value AS parent,\
                c.current_commit_id AS policy_commit_id,\
                c.current_stream_position AS policy_position,c.value AS policy \
         FROM space_current_results s \
         JOIN space_parent_current_results p ON p.space_id=s.space_id AND p.realm_id=s.realm_id \
         JOIN space_child_scope_policy_current_results c ON c.space_id=s.space_id AND c.realm_id=s.realm_id \
         JOIN realm_commits rc ON rc.commit_id=s.current_commit_id \
           AND rc.realm_id=s.realm_id \
           AND rc.stream_position=s.current_stream_position \
           AND rc.stream_ref->>'kind'='realm' \
           AND rc.stream_ref->>'realm_id'=s.realm_id \
         JOIN realm_commits pc ON pc.commit_id=p.current_commit_id AND pc.realm_id=p.realm_id AND pc.stream_position=p.current_stream_position AND pc.stream_ref=rc.stream_ref \
         JOIN realm_commits qc ON qc.commit_id=c.current_commit_id AND qc.realm_id=c.realm_id AND qc.stream_position=c.current_stream_position AND qc.stream_ref=rc.stream_ref \
         WHERE s.space_id=$1 AND s.realm_id=$2 AND s.current_stream_position<$3 \
         FOR SHARE OF s,p,c",
    )
    .bind::<Text, _>(parent_id)
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<BigInt, _>(position)
    .get_result::<ParentCurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| reject("space_parent_unreadable"))?;
    debug_assert_eq!(parent.realm_id, event.realm_id.as_str());
    if parent.parent_position >= position || parent.policy_position >= position {
        return Err(reject("space_parent_unreadable"));
    }
    if parent.space.get("state") != Some(&json!("active")) {
        return Err(reject("space_not_active"));
    }
    if parent.space.get("scope_circle_id").is_some() {
        return Err(reject("space_parent_unreadable"));
    }
    if parent
        .parent
        .as_object()
        .is_none_or(|value| value.len() != 1 || !value.contains_key("parent_space_id"))
    {
        return Err(reject("space_parent_unreadable"));
    }
    match &parent.policy {
        Value::Null => {}
        Value::Object(policy) if policy.get("kind") == Some(&json!("allow_any")) => {}
        Value::Object(policy) if policy.get("kind") == Some(&json!("require_same_scope")) => {}
        _ => return Err(reject(arkret_wire::ErrorCode::POLICY_VIOLATION)),
    }
    Ok(())
}

pub(crate) async fn commit_space_create_current_results_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::SpaceCreate {
        return Ok(());
    }
    if commit.stream_ref
        != (arkret_wire::CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        })
    {
        return Err(reject("Space create requires the Realm commit stream"));
    }
    // The route bypasses the old in-process reducer preflight. Its capability
    // verdict and quota reservation must therefore be fixed by the same
    // locked PG cut as these result writes.
    crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
        conn,
        event,
        commit.committed_at,
    )
    .await?;
    let values = space_create_current_values(event)?;
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| reject("invalid Space stream position"))?;
    require_parent_in_connection(conn, event, position, &values).await?;
    let rows = [
        ("space_current_results", &values.space),
        ("space_parent_current_results", &values.parent),
        (
            "space_child_scope_policy_current_results",
            &values.child_scope_policy,
        ),
    ];
    for (table, value) in rows {
        let query = format!(
            "INSERT INTO {table} \
             (realm_id,space_id,current_commit_id,current_stream_position,value,updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING"
        );
        let inserted = diesel::sql_query(query)
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(values.space_id.as_str())
            .bind::<Text, _>(commit.commit_id.as_str())
            .bind::<BigInt, _>(position)
            .bind::<Jsonb, _>(value)
            .bind::<Timestamptz, _>(commit.committed_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        if inserted != 1 {
            return Err(reject("Space current result already exists"));
        }
    }
    Ok(())
}

/// `ak.space.archive` / `ak.space.restore`: advance the `space` family's
/// lifecycle at the accepting cut (event-kind-registry `result_writes`,
/// `realm-and-space.md` section 3.4).
///
/// Only the four derived members `state`, `state_changed_at`, `updated_by`
/// and `updated_at` move; every other member is retained verbatim, and no
/// child Space or contained Strand is touched. Archive starts only from
/// `active` (`space_not_active`), restore only from `archived`
/// (`space_not_archived`), and a tombstoned Space refuses both
/// (`space_already_terminal`); a refusal writes nothing. `authorize` is the
/// governing Station's same-cut capability verdict; a verified replica fold
/// passes `false` and replays only the value transition.
pub(crate) async fn commit_space_transition_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    authorize: bool,
) -> PersistenceResult<()> {
    use arkret_wire::{EventKind, SpaceState};
    if !matches!(
        event.kind,
        EventKind::SpaceArchive | EventKind::SpaceRestore | EventKind::SpaceTombstone
    ) {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let realm_scope = arkret_wire::ScopeRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    if event.scope_ref != realm_scope
        || commit.stream_ref != realm_stream
        || commit.event_ref != event.event_id
    {
        return Err(reject(
            "Space lifecycle requires a Realm-scope authority cut",
        ));
    }
    let payload_value = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let space_id = if event.kind == EventKind::SpaceTombstone {
        serde_json::from_value::<
            arkret_models_collaboration::object_lifecycle::SpaceObjectTombstonePayload,
        >(payload_value)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
        .space_id
    } else {
        serde_json::from_value::<
            arkret_models_collaboration::object_lifecycle::SpaceStateTransitionPayload,
        >(payload_value)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
        .space_id
    };
    if authorize {
        crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
            conn,
            event,
            commit.committed_at,
        )
        .await?;
    }
    let row = diesel::sql_query(
        "SELECT current_commit_id,current_stream_position,value FROM space_current_results \
         WHERE realm_id=$1 AND space_id=$2 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(space_id.as_str())
    .get_result::<SpaceCurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| reject("Space lifecycle target has no confirmed current value"))?;
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| reject("invalid Space stream position"))?;
    if row.current_stream_position >= position || row.current_commit_id == commit.commit_id.as_str()
    {
        return Err(reject("Space current revision does not precede transition"));
    }
    let current: arkret_models_collaboration::objects::space::Space =
        serde_json::from_value(row.value.clone()).map_err(PersistenceError::database)?;
    if current.id.as_ref() != Some(&space_id) || current.realm_id != event.realm_id {
        return Err(reject("Space lifecycle target identity differs"));
    }
    if current.scope_circle_id.is_some() {
        return Err(reject("Circle-scoped Space needs a Circle authority cut"));
    }
    if authorize && event.kind == EventKind::SpaceTombstone {
        require_no_live_dependents_in_connection(conn, &event.realm_id, &space_id).await?;
    }
    let next = match (&event.kind, current.state.unwrap_or(SpaceState::Active)) {
        (_, SpaceState::Tombstoned) => {
            return Err(reject_lifecycle(
                coland_storage::ConflictCode::SpaceAlreadyTerminal,
                "Space lifecycle target is tombstoned",
            ));
        }
        (EventKind::SpaceTombstone, _) => "tombstoned",
        (EventKind::SpaceArchive, SpaceState::Active) => "archived",
        (EventKind::SpaceArchive, SpaceState::Archived) => {
            return Err(reject_lifecycle(
                coland_storage::ConflictCode::SpaceNotActive,
                "Space archive target is not active",
            ));
        }
        (_, SpaceState::Archived) => "active",
        (_, SpaceState::Active) => {
            return Err(reject_lifecycle(
                coland_storage::ConflictCode::SpaceNotArchived,
                "Space restore target is not archived",
            ));
        }
    };
    let lifecycle_time = Value::String(arkret_canonical::format_timestamp_canonical(
        event.created_at.max(commit.committed_at),
    ));
    let mut post = row.value.clone();
    post["state"] = Value::String(next.to_owned());
    post["state_changed_at"] = lifecycle_time.clone();
    post["updated_by"] =
        serde_json::to_value(&event.actor_id).map_err(PersistenceError::database)?;
    post["updated_at"] = lifecycle_time;
    let _: arkret_models_collaboration::objects::space::Space =
        serde_json::from_value(post.clone()).map_err(PersistenceError::database)?;
    let changed = diesel::sql_query(
        "UPDATE space_current_results SET current_commit_id=$3,current_stream_position=$4,\
         value=$5,updated_at=$6 WHERE realm_id=$1 AND space_id=$2 AND current_commit_id=$7",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(space_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&post)
    .bind::<Timestamptz, _>(commit.committed_at)
    .bind::<Text, _>(&row.current_commit_id)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(reject("Space current changed before transition"));
    }
    Ok(())
}
/// Update metadata and its independent child-policy cell atomically.
pub(crate) async fn commit_space_update_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    authorize: bool,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::events_payloads::space::SpacePatchPayload;
    use arkret_models_collaboration::objects::space::{ChildScopePolicy, Space};
    if event.kind != arkret_wire::EventKind::SpaceUpdate {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let payload: SpacePatchPayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if event.scope_ref
        != (arkret_wire::ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        })
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.event_ref != event.event_id
    {
        return Err(reject("Space update requires the Realm authority cut"));
    }
    if authorize {
        crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
            conn,
            event,
            commit.committed_at,
        )
        .await?;
    }
    let row = diesel::sql_query("SELECT current_commit_id,current_stream_position,value FROM space_current_results WHERE realm_id=$1 AND space_id=$2 FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.space_id.as_str())
        .get_result::<SpaceCurrentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| reject("Space update target is absent"))?;
    let current: Space =
        serde_json::from_value(row.value.clone()).map_err(PersistenceError::database)?;
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| reject("invalid Space stream position"))?;
    if current.id.as_ref() != Some(&payload.space_id)
        || current.realm_id != event.realm_id
        || current.scope_circle_id.is_some()
        || row.current_stream_position >= position
    {
        return Err(reject(
            "Space update target has inconsistent scope or revision",
        ));
    }
    if current.state != Some(arkret_wire::SpaceState::Active) {
        return Err(reject_lifecycle(
            coland_storage::ConflictCode::SpaceNotActive,
            "Space update target is not active",
        ));
    }
    if let Some(expected) = &payload.expected_state_digest {
        let actual = arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(&row.value)
                .map_err(PersistenceError::database)?,
        );
        if expected.as_str() != actual {
            return Err(reject("Space expected_state_digest differs from current"));
        }
    }
    if let Some(policy) = &payload.child_scope_policy {
        if let ChildScopePolicy::RequireScopeCircleId { scope_circle_id } = policy {
            let circle = diesel::sql_query("SELECT current_commit_id,current_stream_position,value FROM circle_current_results WHERE realm_id=$1 AND circle_id=$2 FOR SHARE")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(scope_circle_id.as_str())
                .get_result::<SpaceCurrentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            if !circle.is_some_and(|row| row.value.get("state") == Some(&json!("active"))) {
                return Err(reject("child scope policy Circle is absent or inactive"));
            }
        }
        let value = serde_json::to_value(policy).map_err(PersistenceError::database)?;
        let changed = diesel::sql_query("UPDATE space_child_scope_policy_current_results SET current_commit_id=$3,current_stream_position=$4,value=$5,updated_at=$6 WHERE realm_id=$1 AND space_id=$2 AND current_stream_position<$4")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.space_id.as_str())
            .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(position)
            .bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(commit.committed_at)
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        if changed != 1 {
            return Err(reject("Space policy current is missing or not earlier"));
        }
    }
    if let Some(patch) = &payload.patch {
        for (path, _) in patch.iter() {
            let root = path.split('.').next().unwrap_or(path);
            if !matches!(
                root,
                "kind"
                    | "rank"
                    | "schema_refs"
                    | "title"
                    | "summary"
                    | "labels"
                    | "fields"
                    | "avatar_blob_ref"
                    | "encrypted_metadata"
            ) || arkret_wire::patch::reducer_managed_patch_reason("space", path).is_some()
                || arkret_wire::forbidden_wire::forbidden_wire_path_hard_reject(
                    "space_patch_payload",
                    path,
                )
            {
                return Err(PersistenceError::SchemaViolation(format!(
                    "Space update patch path is forbidden: {path}"
                )));
            }
        }
        let mut post = patch
            .apply_for_typed_target(&row.value, payload.space_id.as_str())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        post["updated_by"] =
            serde_json::to_value(&event.actor_id).map_err(PersistenceError::database)?;
        post["updated_at"] = json!(arkret_canonical::format_timestamp_canonical(
            event.created_at.max(commit.committed_at)
        ));
        let next: Space = serde_json::from_value(post.clone())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        next.validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let changed = diesel::sql_query("UPDATE space_current_results SET current_commit_id=$3,current_stream_position=$4,value=$5,updated_at=$6 WHERE realm_id=$1 AND space_id=$2 AND current_commit_id=$7")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.space_id.as_str())
            .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(position)
            .bind::<Jsonb,_>(&post).bind::<Timestamptz,_>(commit.committed_at)
            .bind::<Text,_>(&row.current_commit_id).execute(&mut *conn).await.map_err(PersistenceError::database)?;
        if changed != 1 {
            return Err(reject("Space current changed before update"));
        }
    }
    Ok(())
}

/// Prove one foreign ordinary Space readable without loading its Realm snapshot.
/// A global object lookup only supplies an internal candidate; the Account's
/// proven read interval and the exact registered sibling sources authorize it.
async fn foreign_parent_is_readable(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    parent_id: &arkret_wire::SpaceId,
) -> PersistenceResult<bool> {
    use arkret_models_collaboration::objects::space::{ChildScopePolicy, Space};
    #[derive(diesel::QueryableByName)]
    struct Candidate {
        #[diesel(sql_type = Text)]
        realm_id: String,
        #[diesel(sql_type = Jsonb)]
        space: Value,
        #[diesel(sql_type = Jsonb)]
        parent: Value,
        #[diesel(sql_type = Jsonb)]
        policy: Value,
        #[diesel(sql_type = Jsonb)]
        space_revision: Value,
        #[diesel(sql_type = Jsonb)]
        parent_revision: Value,
        #[diesel(sql_type = Jsonb)]
        policy_revision: Value,
        #[diesel(sql_type = diesel::sql_types::Bool)]
        covered: bool,
    }
    let candidate = diesel::sql_query("SELECT s.realm_id,s.value AS space,p.value AS parent,c.value AS policy,jsonb_build_object('commit_id',s.current_commit_id,'stream_position',s.current_stream_position) AS space_revision,jsonb_build_object('commit_id',p.current_commit_id,'stream_position',p.current_stream_position) AS parent_revision,jsonb_build_object('commit_id',c.current_commit_id,'stream_position',c.current_stream_position) AS policy_revision,(se.pk IS NOT NULL AND pe.pk IS NOT NULL AND ce.pk IS NOT NULL) AS covered FROM space_current_results s JOIN realm_authorities a ON a.realm_id=s.realm_id AND a.generation=0 JOIN space_parent_current_results p ON p.realm_id=s.realm_id AND p.space_id=s.space_id JOIN space_child_scope_policy_current_results c ON c.realm_id=s.realm_id AND c.space_id=s.space_id LEFT JOIN realm_commits sc ON sc.realm_id=s.realm_id AND sc.commit_id=s.current_commit_id AND sc.stream_position=s.current_stream_position AND sc.stream_ref->>'kind'='realm' AND sc.stream_ref->>'realm_id'=s.realm_id LEFT JOIN canonical_events se ON se.pk=sc.event_pk AND se.state='committed' LEFT JOIN realm_commits pc ON pc.realm_id=p.realm_id AND pc.commit_id=p.current_commit_id AND pc.stream_position=p.current_stream_position AND pc.stream_ref=jsonb_build_object('kind','realm','realm_id',s.realm_id) LEFT JOIN canonical_events pe ON pe.pk=pc.event_pk AND pe.state='committed' LEFT JOIN realm_commits cc ON cc.realm_id=c.realm_id AND cc.commit_id=c.current_commit_id AND cc.stream_position=c.current_stream_position AND cc.stream_ref=jsonb_build_object('kind','realm','realm_id',s.realm_id) LEFT JOIN canonical_events ce ON ce.pk=cc.event_pk AND ce.state='committed' WHERE s.space_id=$1 AND s.realm_id<>$2")
        .bind::<Text,_>(parent_id.as_str()).bind::<Text,_>(event.realm_id.as_str())
        .get_result::<Candidate>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(candidate) = candidate else {
        return Ok(false);
    };
    let Ok(space) = serde_json::from_value::<Space>(candidate.space.clone()) else {
        return Ok(false);
    };
    if space.validate().is_err()
        || space.id.as_ref() != Some(parent_id)
        || space.realm_id.as_str() != candidate.realm_id
        || space.scope_circle_id.is_some()
        || space.parent_space_id.is_some()
        || space.child_scope_policy.is_some()
        || candidate
            .parent
            .as_object()
            .is_none_or(|members| members.len() != 1 || !members.contains_key("parent_space_id"))
        || serde_json::from_value::<Option<arkret_wire::SpaceId>>(
            candidate.parent["parent_space_id"].clone(),
        )
        .is_err()
        || serde_json::from_value::<Option<ChildScopePolicy>>(candidate.policy.clone()).is_err()
    {
        return Ok(false);
    }
    if !candidate.covered {
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: space.realm_id.clone(),
        };
        let selectors = [
            arkret_wire::CurrentSelector::Space {
                space_id: parent_id.clone(),
            },
            arkret_wire::CurrentSelector::SpaceParent {
                space_id: parent_id.clone(),
            },
            arkret_wire::CurrentSelector::SpaceChildScopePolicy {
                space_id: parent_id.clone(),
            },
        ];
        let Some((_, entries)) =
            crate::replica_authorization::exact_current_evidence(conn, &stream, &selectors).await?
        else {
            return Ok(false);
        };
        for (entry, (stored_revision, stored_value)) in entries.iter().zip([
            (&candidate.space_revision, &candidate.space),
            (&candidate.parent_revision, &candidate.parent),
            (&candidate.policy_revision, &candidate.policy),
        ]) {
            let arkret_wire::TypedCurrentRow::Value {
                revision, value, ..
            } = entry;
            let Ok(stored_revision) =
                serde_json::from_value::<arkret_wire::CurrentRevision>(stored_revision.clone())
            else {
                return Ok(false);
            };
            if revision != &stored_revision || value != stored_value {
                return Ok(false);
            }
        }
    }
    #[derive(diesel::QueryableByName)]
    struct Membership {
        #[diesel(sql_type = Text)]
        membership: String,
    }
    let membership = diesel::sql_query("SELECT membership FROM member_state_current_results WHERE realm_id=$1 AND member_id=$2 FOR SHARE")
        .bind::<Text,_>(candidate.realm_id.as_str()).bind::<Text,_>(event.actor_id.to_string())
        .get_result::<Membership>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if membership.is_none_or(|row| row.membership != "join") {
        return Ok(false);
    }
    Ok(
        crate::account_stream_scan::snapshot_realm_floor_in_connection(
            conn,
            &space.realm_id,
            &event.actor_id,
        )
        .await?
        .is_some(),
    )
}

/// Reparent only the registered structural cell, at the accepting Realm cut.
pub(crate) async fn commit_space_parent_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::events_payloads::space::SpaceParentPayload;
    use arkret_models_collaboration::objects::space::Space;
    if event.kind != arkret_wire::EventKind::SpaceParent {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let payload: SpaceParentPayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if event.scope_ref
        != (arkret_wire::ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        })
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.event_ref != event.event_id
    {
        return Err(reject("Space parent requires a Realm-scope authority cut"));
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
        conn,
        event,
        commit.committed_at,
    )
    .await?;
    let metadata = diesel::sql_query("SELECT current_commit_id,current_stream_position,value FROM space_current_results WHERE realm_id=$1 AND space_id=$2 FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.space_id.as_str())
        .get_result::<SpaceCurrentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| reject("space_parent_unreadable"))?;
    let child: Space =
        serde_json::from_value(metadata.value.clone()).map_err(PersistenceError::database)?;
    if child.id.as_ref() != Some(&payload.space_id)
        || child.realm_id != event.realm_id
        || child.scope_circle_id.is_some()
    {
        return Err(reject("space_parent_unreadable"));
    }
    if child.state.unwrap_or(arkret_wire::SpaceState::Active) != arkret_wire::SpaceState::Active {
        return Err(reject("space_not_active"));
    }
    let row = diesel::sql_query("SELECT current_commit_id,current_stream_position,value FROM space_parent_current_results WHERE realm_id=$1 AND space_id=$2 FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.space_id.as_str())
        .get_result::<SpaceCurrentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| reject("space_parent_unreadable"))?;
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| reject("invalid Space stream position"))?;
    if row.current_stream_position >= position || metadata.current_stream_position >= position {
        return Err(reject("Space parent basis does not precede transition"));
    }
    if row.value != json!({"parent_space_id":payload.expected_parent_space_id}) {
        return Err(reject("space_parent_mismatch"));
    }
    let values = SpaceCreateValues {
        space_id: payload.space_id.clone(),
        space: metadata.value,
        parent: json!({"parent_space_id":payload.parent_space_id}),
        child_scope_policy: Value::Null,
    };
    if payload.parent_space_id.as_ref() == Some(&payload.space_id) {
        return Err(reject("space_parent_cycle"));
    }
    if let Some(parent_id) = &payload.parent_space_id
        && foreign_parent_is_readable(conn, event, parent_id).await?
    {
        return Err(reject("space_realm_mismatch"));
    }
    require_parent_in_connection(conn, event, position, &values).await?;
    let mut next = payload.parent_space_id.clone();
    let mut seen = std::collections::BTreeSet::new();
    while let Some(id) = next {
        if id == payload.space_id || !seen.insert(id.clone()) {
            return Err(reject("space_parent_cycle"));
        }
        let ancestor = diesel::sql_query("SELECT s.realm_id,s.value AS space,p.current_stream_position AS parent_position,p.value AS parent,c.current_stream_position AS policy_position,c.value AS policy FROM space_current_results s JOIN space_parent_current_results p ON p.realm_id=s.realm_id AND p.space_id=s.space_id JOIN space_child_scope_policy_current_results c ON c.realm_id=s.realm_id AND c.space_id=s.space_id JOIN realm_commits sc ON sc.realm_id=s.realm_id AND sc.commit_id=s.current_commit_id AND sc.stream_position=s.current_stream_position AND sc.stream_ref->>'kind'='realm' AND sc.stream_ref->>'realm_id'=s.realm_id JOIN realm_commits pc ON pc.realm_id=p.realm_id AND pc.commit_id=p.current_commit_id AND pc.stream_position=p.current_stream_position AND pc.stream_ref=sc.stream_ref JOIN realm_commits cc ON cc.realm_id=c.realm_id AND cc.commit_id=c.current_commit_id AND cc.stream_position=c.current_stream_position AND cc.stream_ref=sc.stream_ref WHERE s.space_id=$1 AND s.current_stream_position<$2 FOR SHARE OF s,p,c")
            .bind::<Text,_>(id.as_str()).bind::<BigInt,_>(position)
            .get_result::<ParentCurrentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
            .ok_or_else(|| reject("space_parent_unreadable"))?;
        let ancestor_space: Space =
            serde_json::from_value(ancestor.space).map_err(PersistenceError::database)?;
        if ancestor_space.scope_circle_id.is_some()
            || ancestor.parent_position >= position
            || ancestor.policy_position >= position
        {
            return Err(reject("space_parent_unreadable"));
        }
        if ancestor.realm_id != event.realm_id.as_str() {
            return Err(reject("space_realm_mismatch"));
        }
        if ancestor
            .parent
            .as_object()
            .is_none_or(|members| members.len() != 1 || !members.contains_key("parent_space_id"))
        {
            return Err(reject("space_parent_unreadable"));
        }
        next = serde_json::from_value(ancestor.parent["parent_space_id"].clone())
            .map_err(PersistenceError::database)?;
    }
    let changed = diesel::sql_query("UPDATE space_parent_current_results SET current_commit_id=$3,current_stream_position=$4,value=$5,updated_at=$6 WHERE realm_id=$1 AND space_id=$2 AND current_commit_id=$7")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.space_id.as_str())
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(position)
        .bind::<Jsonb,_>(&values.parent).bind::<Timestamptz,_>(commit.committed_at)
        .bind::<Text,_>(&row.current_commit_id).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(reject("Space parent changed before transition"));
    }
    Ok(())
}

pub(crate) async fn require_no_live_dependents_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    space_id: &arkret_wire::SpaceId,
) -> PersistenceResult<()> {
    let row = diesel::sql_query("SELECT (EXISTS (SELECT 1 FROM space_parent_current_results p LEFT JOIN space_current_results s ON s.realm_id=p.realm_id AND s.space_id=p.space_id WHERE p.realm_id=$1 AND p.value->>'parent_space_id'=$2 AND (s.value->>'state' IS NULL OR s.value->>'state'<>'tombstoned')) OR EXISTS (SELECT 1 FROM strand_position_current_results p LEFT JOIN strand_current_results s ON s.realm_id=p.realm_id AND s.strand_id=p.strand_id WHERE p.realm_id=$1 AND p.value<>'null'::jsonb AND (p.board_space_id=$2 OR p.value->>'list_space_id'=$2) AND (s.value->>'state' IS NULL OR s.value->>'state' NOT IN ('redacted','tombstoned'))) OR EXISTS (SELECT 1 FROM strand_current_results s WHERE s.realm_id=$1 AND s.value#>>'{topic,space_id}'=$2 AND (s.value->>'state' IS NULL OR s.value->>'state' NOT IN ('redacted','tombstoned')))) AS present")
        .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(space_id.as_str())
        .get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if row.present {
        return Err(PersistenceError::Conflict(format!(
            "{}: Space has live dependents",
            coland_storage::ConflictCode::SpaceHasLiveDependents
        )));
    }
    Ok(())
}
