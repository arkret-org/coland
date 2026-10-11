//! Shared Pin admission and its immutable dot-set projection at one Commit cut.

use arkret_models_collaboration::objects::productivity::{
    PinAssertionEntry, PinAssertionPayload, PinCurrentValue,
};
use arkret_wire::{CommitStreamRef, EventKind, PinScope, ScopeRef};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::OptionalExtension;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

#[derive(diesel::QueryableByName)]
struct CurrentRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Jsonb)]
    stream_ref: Value,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

#[derive(diesel::QueryableByName)]
struct EventRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

fn absent() -> PersistenceError {
    PersistenceError::NotFound("pin target not found".into())
}

async fn object_scope(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    id: &str,
) -> PersistenceResult<ScopeRef> {
    if let Ok(message) = arkret_wire::MessageId::new(id) {
        return crate::message_revision_current_results::locked_message_target(
            conn, realm, &message,
        )
        .await
        .map(|target| target.scope_ref)
        .map_err(|error| match error {
            PersistenceError::NotFound(_) => absent(),
            other => other,
        });
    }
    let (table, key) = if arkret_wire::StrandId::new(id).is_ok() {
        ("strand_current_results", "strand_id")
    } else if arkret_wire::SpaceId::new(id).is_ok() {
        ("space_current_results", "space_id")
    } else if arkret_wire::RelationId::new(id).is_ok() {
        ("relation_current_results", "relation_id")
    } else {
        return Err(absent());
    };
    let query = format!(
        "SELECT s.value,c.stream_ref,s.current_stream_position FROM {table} s JOIN realm_commits c ON c.realm_id=s.realm_id AND c.commit_id=s.current_commit_id WHERE s.realm_id=$1 AND s.{key}=$2 FOR SHARE OF s"
    );
    let row = diesel::sql_query(query)
        .bind::<Text, _>(realm.as_str())
        .bind::<Text, _>(id)
        .get_result::<CurrentRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(absent)?;
    let stream: CommitStreamRef =
        serde_json::from_value(row.stream_ref).map_err(PersistenceError::database)?;
    let circle = row
        .value
        .get("scope_circle_id")
        .filter(|value| !value.is_null())
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .map_err(PersistenceError::database)?;
    match stream {
        CommitStreamRef::Realm { realm_id } if realm_id == *realm => Ok(match circle {
            Some(circle_id) => ScopeRef::Circle {
                realm_id,
                circle_id,
            },
            None => ScopeRef::Realm { realm_id },
        }),
        CommitStreamRef::Circle {
            realm_id,
            circle_id,
        } if realm_id == *realm => Ok(ScopeRef::Circle {
            realm_id,
            circle_id,
        }),
        _ => Err(absent()),
    }
}

pub(crate) async fn pin_scope_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    home: &PinScope,
) -> PersistenceResult<ScopeRef> {
    match home {
        PinScope::Realm { id } if id == realm => Ok(ScopeRef::Realm {
            realm_id: realm.clone(),
        }),
        PinScope::Circle { id } => {
            let row = diesel::sql_query("SELECT s.value,c.stream_ref,s.current_stream_position FROM circle_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id WHERE s.realm_id=$1 AND s.circle_id=$2 AND s.value->>'state'='active' FOR SHARE OF s")
                .bind::<Text,_>(realm.as_str()).bind::<Text,_>(id.as_str())
                .get_result::<CurrentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            if row.is_none() {
                return Err(absent());
            }
            Ok(ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: id.clone(),
            })
        }
        PinScope::Strand { id } => object_scope(conn, realm, id.as_str()).await,
        PinScope::Space { id } => object_scope(conn, realm, id.as_str()).await,
        _ => Err(absent()),
    }
}

pub(crate) async fn commit_pin_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    authorize: bool,
) -> PersistenceResult<()> {
    if !matches!(
        event.kind,
        EventKind::PinAdd | EventKind::PinRemove | EventKind::PinReorder
    ) {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let payload = PinAssertionPayload::from_event(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let home = payload.pin_scope().clone();
    let effective = if authorize {
        pin_scope_in_connection(conn, &event.realm_id, &home).await?
    } else {
        event.scope_ref.clone()
    };
    let stream = CommitStreamRef::from_scope(&effective, Some(event.realm_id.clone()))
        .map_err(PersistenceError::database)?;
    if effective != event.scope_ref
        || stream != commit.stream_ref
        || commit.event_ref != event.event_id
    {
        return Err(absent());
    }
    if authorize {
        crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
            conn,
            event,
            commit.committed_at,
        )
        .await?;
        if matches!(effective, ScopeRef::Circle { .. }) {
            crate::circle_current_results::require_active_author_in_connection(conn, event, commit)
                .await?;
        }
        let target = object_scope(conn, &event.realm_id, payload.target_ref()).await?;
        if target != effective && !matches!(target, ScopeRef::Realm { .. }) {
            return Err(absent());
        }
    }
    let subject =
        arkret_canonical::canonical_json_string(&home).map_err(PersistenceError::database)?;
    let position = i64::try_from(commit.stream_position).map_err(PersistenceError::database)?;
    let prior = diesel::sql_query("SELECT value,source_stream_ref AS stream_ref,current_stream_position FROM pin_current_results WHERE realm_id=$1 AND pin_scope_key=$2 FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&subject)
        .get_result::<CurrentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let mut value = match prior {
        Some(row) => {
            if row.stream_ref
                != serde_json::to_value(&stream).map_err(PersistenceError::database)?
                || row.current_stream_position >= position
            {
                return Err(PersistenceError::Conflict(
                    "failed_precondition: pin source prefix differs".into(),
                ));
            }
            serde_json::from_value::<PinCurrentValue>(row.value)
                .map_err(PersistenceError::database)?
        }
        None => PinCurrentValue::new(Vec::new()).map_err(PersistenceError::database)?,
    };
    value
        .validate_for_scope(&home)
        .map_err(PersistenceError::database)?;
    if authorize && (event.kind == EventKind::PinReorder || payload.expected_rank().is_some()) {
        // One exact projection home belongs to one accepting stream. Read the
        // newest assertion for this target from that proved stream prefix;
        // canonical dot order is never used as a winner.
        let prior = diesel::sql_query("SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=e.realm_id WHERE e.realm_id=$1 AND e.state='committed' AND e.kind IN ('ak.pin.add','ak.pin.remove','ak.pin.reorder') AND e.envelope->'payload'->'pin_scope'=$2 AND e.envelope->'payload'->>'target_ref'=$3 AND c.stream_ref=$4 AND c.stream_position<$5 ORDER BY c.stream_position DESC LIMIT 1")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&home).map_err(PersistenceError::database)?)
            .bind::<Text,_>(payload.target_ref()).bind::<Jsonb,_>(serde_json::to_value(&stream).map_err(PersistenceError::database)?)
            .bind::<BigInt,_>(position).get_result::<EventRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let rank = prior
            .as_ref()
            .filter(|row| row.envelope.get("kind").and_then(Value::as_str) != Some("ak.pin.remove"))
            .and_then(|row| row.envelope.pointer("/payload/rank"))
            .and_then(Value::as_str);
        if event.kind == EventKind::PinReorder && rank.is_none() {
            return Err(PersistenceError::Conflict(
                "pin_target_not_pinned: target has no live add assertion".into(),
            ));
        }
        if payload
            .expected_rank()
            .is_some_and(|expected| rank != Some(expected))
        {
            return Err(PersistenceError::Conflict(
                "failed_precondition: pin expected_rank differs".into(),
            ));
        }
    }
    value
        .add_assertion(PinAssertionEntry {
            tag_id: arkret_models_collaboration::exact_current_results::CanonicalEventDot::new(
                event.event_id.clone(),
                0,
            )
            .map_err(PersistenceError::database)?,
            value: payload,
        })
        .map_err(PersistenceError::database)?;
    diesel::sql_query("INSERT INTO pin_current_results (realm_id,pin_scope_key,pin_scope,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$8,$4,$5,$6,$7) ON CONFLICT(realm_id,pin_scope_key) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&subject)
        .bind::<Jsonb,_>(serde_json::to_value(&home).map_err(PersistenceError::database)?)
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(position)
        .bind::<Jsonb,_>(serde_json::to_value(&value).map_err(PersistenceError::database)?)
        .bind::<Timestamptz,_>(commit.committed_at)
        .bind::<Jsonb,_>(serde_json::to_value(&stream).map_err(PersistenceError::database)?)
        .execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}
