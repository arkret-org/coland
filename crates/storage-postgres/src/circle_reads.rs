//! Circle convenience reads from accepted current cells in one snapshot.

use arkret_models_collaboration::governance::circle::{
    Circle, CircleDirectoryVisibility, CircleMemberCountBucket, CircleMembership, CirclePreview,
    CirclePreviewDisplay, CirclePreviewVisibility, CircleReadView, CircleState, CircleView,
};
use arkret_wire::{ActorId, CircleId, RealmId};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Bool, Jsonb, Nullable, Text};
use diesel_async::{AsyncConnection as _, AsyncPgConnection};
use horme::RunQueryDsl;
use sha2::{Digest, Sha256};

use crate::{PgPool, PgTransactionError, pg_conn};

#[derive(diesel::QueryableByName)]
struct CircleRow {
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type=Nullable<Jsonb>)]
    envelope: Option<serde_json::Value>,
    #[diesel(sql_type=Nullable<Jsonb>)]
    commit_json: Option<serde_json::Value>,
    #[diesel(sql_type=Bool)]
    verified_current: bool,
    #[diesel(sql_type=Text)]
    circle_id: String,
}

#[derive(diesel::QueryableByName)]
struct MemberRow {
    #[diesel(sql_type=Text)]
    member_id: String,
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type=Nullable<Jsonb>)]
    envelope: Option<serde_json::Value>,
    #[diesel(sql_type=Nullable<Jsonb>)]
    commit_json: Option<serde_json::Value>,
    #[diesel(sql_type=Bool)]
    verified_current: bool,
}

#[derive(diesel::QueryableByName)]
struct AcceptedGroupRow {
    #[diesel(sql_type=Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type=Nullable<Jsonb>)]
    envelope: Option<serde_json::Value>,
    #[diesel(sql_type=Nullable<Jsonb>)]
    commit_json: Option<serde_json::Value>,
    #[diesel(sql_type=Bool)]
    verified_current: bool,
}

fn corrupt(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!("invalid accepted Circle current: {detail}"))
}

fn preview_commitment(realm: &RealmId, circle: &CircleId) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ak.circle.preview.v1\0");
    digest.update(realm.as_str().as_bytes());
    digest.update([0]);
    digest.update(circle.as_str().as_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn covering_event(
    envelope: Option<serde_json::Value>,
    commit: Option<serde_json::Value>,
    verified_current: bool,
) -> PersistenceResult<Option<arkret_wire::Event>> {
    // A verified Snapshot can disclose current without disclosing its Event.
    let (envelope, commit) = match (envelope, commit) {
        (Some(envelope), Some(commit)) => (envelope, commit),
        (None, None) if verified_current => return Ok(None),
        (None, Some(commit)) if verified_current => {
            let _: arkret_wire::RealmCommit = serde_json::from_value(commit).map_err(corrupt)?;
            return Ok(None);
        }
        _ => return Err(corrupt("current has no complete accepted provenance")),
    };
    let event: arkret_wire::Event = serde_json::from_value(envelope).map_err(corrupt)?;
    let commit: arkret_wire::RealmCommit = serde_json::from_value(commit).map_err(corrupt)?;
    if commit.event_ref != event.event_id || commit.realm_id != event.realm_id {
        return Err(corrupt("Commit does not cover its canonical Event"));
    }
    Ok(Some(event))
}

fn verified_current_sql(alias: &str, selector: &str) -> String {
    format!(
        "EXISTS(SELECT 1 FROM replica_authorization_rows v \
         JOIN replica_authorization_cuts h ON h.realm_id=v.realm_id \
           AND h.source_stream_ref=v.source_stream_ref \
         WHERE v.realm_id={alias}.realm_id AND v.selector={selector} \
           AND v.source_stream_ref={alias}.source_stream_ref \
           AND v.current_commit_id={alias}.current_commit_id \
           AND v.current_stream_position={alias}.current_stream_position \
           AND v.value={alias}.value AND v.current_stream_position<=h.head_stream_position \
           AND (v.current_stream_position<h.head_stream_position \
                OR v.current_commit_id=h.head_commit_id)) AS verified_current"
    )
}

async fn views(
    conn: &mut AsyncPgConnection,
    realm: Option<&RealmId>,
    circle_id: Option<&CircleId>,
    actor: &ActorId,
) -> PersistenceResult<Vec<CircleReadView>> {
    let circles = diesel::sql_query(format!(
        "SELECT r.value,e.envelope,c.commit_json,r.circle_id,{} FROM circle_current_states r \
         LEFT JOIN realm_commits c ON c.commit_id=r.current_commit_id AND c.realm_id=r.realm_id \
             AND c.stream_position=r.current_stream_position AND c.stream_ref=r.source_stream_ref \
         LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
         WHERE ($1::text IS NULL OR r.realm_id=$1) AND ($2::text IS NULL OR r.circle_id=$2) ORDER BY r.circle_id",
        verified_current_sql("r", "jsonb_build_object('kind','circle','circle_id',r.circle_id)"),
    )).bind::<Nullable<Text>,_>(realm.map(RealmId::as_str)).bind::<Nullable<Text>,_>(circle_id.map(CircleId::as_str))
        .load::<CircleRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut result = Vec::new();
    let at = chrono::Utc::now();
    for row in circles {
        let circle: Circle = serde_json::from_value(row.value).map_err(corrupt)?;
        let id: CircleId = row.circle_id.parse().map_err(corrupt)?;
        if circle.id.as_ref() != Some(&id) {
            return Err(corrupt("Circle current differs from its selector"));
        }
        // The parent terminal Commit closes this live convenience surface.
        // Keep Circle canonical lifecycle, membership and scope unchanged;
        // authorized retained history uses the separate committed read ports.
        let terminal = diesel::sql_query(
            "SELECT EXISTS(SELECT 1 FROM realm_bootstrap_current_states \
             WHERE realm_id=$1 AND state_family IN ('realm_tombstone','realm_destroy')) AS present",
        )
        .bind::<Text, _>(circle.realm_id.as_str())
        .get_result::<crate::ExistsRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if terminal.present {
            continue;
        }
        if let Some(create) = covering_event(row.envelope, row.commit_json, row.verified_current)? {
            let mut payload: arkret_models_collaboration::events_payloads::circle::CircleCreatePayload =
            serde_json::from_value(serde_json::json!(&create.payload)).map_err(corrupt)?;
            payload.object.id = Some(id.clone());
            let object = serde_json::to_value(payload.object).map_err(corrupt)?;
            if create.kind != arkret_wire::EventKind::CircleCreate
                || CircleId::from_event_id(&create.event_id) != id
                || circle.id.as_ref() != Some(&id)
                || circle.realm_id != create.realm_id
                || create.scope_ref
                    != (arkret_wire::ScopeRef::Realm {
                        realm_id: circle.realm_id.clone(),
                    })
                || serde_json::to_value(&circle).map_err(corrupt)? != object
            {
                return Err(corrupt(
                    "profile does not match its covering accepted create",
                ));
            }
        }
        if circle.profile_ref.is_some()
            || circle.title == "Agent Sidecar Scope"
            || circle.display.short_name.starts_with("SC-")
        {
            continue;
        }
        if !crate::authority_commit::accepted_current_member_joined_in_connection(
            conn,
            &circle.realm_id,
            actor,
        )
        .await?
        {
            continue;
        }
        let mut joined = crate::account_stream_scan::caller_circle_floor_in_connection(
            conn,
            &circle.realm_id,
            &id,
            actor,
        )
        .await?
        .is_some();
        let mut member_ids = Vec::new();
        let mut viewer_membership = None;
        let members = diesel::sql_query(format!(
            "SELECT m.member_id,m.value,e.envelope,c.commit_json,{} FROM circle_member_state_current_states m \
             LEFT JOIN realm_commits c ON c.commit_id=m.current_commit_id AND c.realm_id=m.realm_id \
                AND c.stream_position=m.current_stream_position AND c.stream_ref=m.source_stream_ref \
             LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
             WHERE m.realm_id=$1 AND m.circle_id=$2 ORDER BY m.member_id",
            verified_current_sql("m", "jsonb_build_object('kind','circle_member_state','circle_id',m.circle_id,'member_actor_id',m.member_id::jsonb)"),
        )).bind::<Text,_>(circle.realm_id.as_str()).bind::<Text,_>(id.as_str())
            .load::<MemberRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        if joined {
            joined = members
                .iter()
                .find(|member| member.member_id == actor.to_string())
                .map(|member| {
                    serde_json::from_value::<arkret_wire::CircleMemberStateValue>(
                        member.value.clone(),
                    )
                    .map_err(corrupt)
                })
                .transpose()?
                .is_some_and(|current| {
                    current.membership == arkret_wire::MembershipState::Join
                        && current.effective_at <= at
                });
        }
        for member in members {
            let who: ActorId = serde_json::from_str(&member.member_id).map_err(corrupt)?;
            let current: arkret_wire::CircleMemberStateValue =
                serde_json::from_value(member.value).map_err(corrupt)?;
            if let Some(event) =
                covering_event(member.envelope, member.commit_json, member.verified_current)?
                && (event.kind != arkret_wire::EventKind::CircleMemberState
                    || event.scope_ref
                        != (arkret_wire::ScopeRef::Circle {
                            realm_id: circle.realm_id.clone(),
                            circle_id: id.clone(),
                        })
                    || serde_json::from_value::<ActorId>(
                        event
                            .payload
                            .get("member_id")
                            .cloned()
                            .ok_or_else(|| corrupt("member absent"))?,
                    )
                    .map_err(corrupt)?
                        != who
                    || event.payload.get("membership")
                        != Some(&serde_json::to_value(current.membership).map_err(corrupt)?))
            {
                return Err(corrupt(
                    "membership does not match its covering accepted Event",
                ));
            }
            let membership: CircleMembership =
                serde_json::from_value(serde_json::json!(current.membership)).map_err(corrupt)?;
            if who == *actor {
                viewer_membership = Some(membership);
            }
            if membership == CircleMembership::Join
                && current.effective_at <= at
                && crate::account_stream_scan::caller_circle_floor_in_connection(
                    conn,
                    &circle.realm_id,
                    &id,
                    &who,
                )
                .await?
                .is_some()
            {
                member_ids.push(who);
            }
        }
        if !joined {
            if circle.directory_visibility == CircleDirectoryVisibility::RealmMembers
                && circle.state == CircleState::Active
            {
                result.push(CircleReadView::Preview(CirclePreview {
                    circle_id: id.clone(),
                    realm_id: circle.realm_id.clone(),
                    visibility: CirclePreviewVisibility::RealmMembers,
                    display: CirclePreviewDisplay {
                        color_token: circle.display.color_token,
                        symbol: circle.display.symbol,
                    },
                    member_count_bucket: CircleMemberCountBucket::from_count(member_ids.len()),
                    join_rule: circle.join_rule,
                    opaque_commitment: preview_commitment(&circle.realm_id, &id),
                }));
            }
            continue;
        }
        let scope = arkret_wire::ScopeRef::Circle {
            realm_id: circle.realm_id.clone(),
            circle_id: id.clone(),
        };
        let key =
            String::from_utf8(arkret_canonical::canonical_json_bytes(&scope).map_err(corrupt)?)
                .map_err(corrupt)?;
        let groups = diesel::sql_query(
            "SELECT g.value,e.envelope,c.commit_json,false AS verified_current FROM mls_group_current_states g \
             LEFT JOIN realm_commits c ON c.commit_id=g.current_commit_id AND c.realm_id=g.realm_id \
               AND c.stream_position=g.current_stream_position AND c.stream_ref=$3 \
             LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
             WHERE g.scope_key=$1 \
             UNION ALL SELECT v.value,NULL::jsonb,NULL::jsonb,true FROM replica_authorization_rows v \
             JOIN replica_authorization_cuts h ON h.realm_id=v.realm_id AND h.source_stream_ref=v.source_stream_ref \
             WHERE v.selector=$2 AND v.source_stream_ref=$3 \
               AND v.current_stream_position<=h.head_stream_position \
               AND (v.current_stream_position<h.head_stream_position OR v.current_commit_id=h.head_commit_id) \
               AND NOT EXISTS(SELECT 1 FROM mls_group_current_states g WHERE g.scope_key=$1)",
        ).bind::<Text,_>(&key)
            .bind::<Jsonb,_>(serde_json::to_value(arkret_wire::CurrentSelector::MlsGroup { scope_ref: scope.clone() }).map_err(corrupt)?)
            .bind::<Jsonb,_>(serde_json::to_value(arkret_wire::CommitStreamRef::from_scope(&scope, None).map_err(corrupt)?).map_err(corrupt)?)
            .load::<AcceptedGroupRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let mls_group_id = if let Some(group) = groups.into_iter().next() {
            let current: arkret_wire::MlsGroupValue =
                serde_json::from_value(group.value).map_err(corrupt)?;
            if current.effective_scope != scope {
                return Err(corrupt("MLS current differs from its scope"));
            }
            if let Some(event) =
                covering_event(group.envelope, group.commit_json, group.verified_current)?
                && (event.scope_ref != scope
                    || !matches!(
                        event.kind,
                        arkret_wire::EventKind::MlsGenesis | arkret_wire::EventKind::MlsCommit
                    ))
            {
                return Err(corrupt(
                    "MLS current has no matching covering accepted transition",
                ));
            }
            Some(scope.canonical_mls_group_id().map_err(corrupt)?.to_string())
        } else {
            None
        };
        result.push(CircleReadView::Full(CircleView {
            circle_id: id,
            realm_id: circle.realm_id,
            profile_ref: circle.profile_ref,
            title: circle.title,
            summary: circle.summary,
            display: circle.display,
            directory_visibility: circle.directory_visibility,
            join_rule: circle.join_rule,
            history_access: circle.history_access,
            mls_group_id,
            state: circle.state,
            viewer_membership,
            member_ids,
            created_by: circle.created_by,
            created_at: circle.created_at,
            updated_by: circle.updated_by,
            updated_at: circle.updated_at,
        }));
    }
    Ok(result)
}

pub(crate) async fn circle_reads_for_actor(
    pool: &PgPool,
    realm: &RealmId,
    actor: &ActorId,
) -> PersistenceResult<Vec<CircleReadView>> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
        views(conn, Some(realm), None, actor)
            .await
            .map_err(PgTransactionError::from)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn circle_read_for_actor(
    pool: &PgPool,
    circle: &CircleId,
    actor: &ActorId,
) -> PersistenceResult<Option<CircleReadView>> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        diesel::sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(conn)
            .await
            .map_err(PersistenceError::database)?;
        Ok(views(conn, None, Some(circle), actor).await?.pop())
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn circle_views_for_actor(
    pool: &PgPool,
    realm: &RealmId,
    actor: &ActorId,
) -> PersistenceResult<Vec<CircleView>> {
    Ok(circle_reads_for_actor(pool, realm, actor)
        .await?
        .into_iter()
        .filter_map(|read| match read {
            CircleReadView::Full(view) => Some(view),
            _ => None,
        })
        .collect())
}

pub(crate) async fn circle_view_for_actor(
    pool: &PgPool,
    circle: &CircleId,
    actor: &ActorId,
) -> PersistenceResult<Option<CircleView>> {
    Ok(match circle_read_for_actor(pool, circle, actor).await? {
        Some(CircleReadView::Full(view)) => Some(view),
        _ => None,
    })
}
