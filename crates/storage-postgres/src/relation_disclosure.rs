//! Same-cut endpoint reference disclosure for complete Relation carriers.

use arkret_wire::relation::{Relation, RelationEndpoint};
use arkret_wire::{ActorId, CommitStreamRef, EventId, RealmId, ScopeRef};

use super::{
    AsyncPgConnection, Jsonb, OptionalExtension, PersistenceError, PersistenceResult,
    QueryableByName, RunQueryDsl, Text, sql_query,
};

#[derive(QueryableByName)]
struct ObjectRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    source_stream_ref: Option<serde_json::Value>,
}

#[derive(QueryableByName)]
struct EventRow {
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
}

async fn scope_visible(
    conn: &mut AsyncPgConnection,
    scope: &ScopeRef,
    caller: &ActorId,
) -> PersistenceResult<bool> {
    Ok(match scope {
        ScopeRef::Realm { realm_id } => {
            crate::account_stream_scan::caller_realm_floor_in_connection(conn, realm_id, caller)
                .await?
                .is_some()
        }
        ScopeRef::Circle {
            realm_id,
            circle_id,
        } => crate::account_stream_scan::caller_circle_floor_in_connection(
            conn, realm_id, circle_id, caller,
        )
        .await?
        .is_some(),
        _ => false,
    })
}

pub(crate) async fn relation_visible_in_connection(
    conn: &mut AsyncPgConnection,
    relation: &Relation,
    caller: &ActorId,
) -> PersistenceResult<bool> {
    let scope = match &relation.scope_circle_id {
        Some(circle_id) => ScopeRef::Circle {
            realm_id: relation.realm_id.clone(),
            circle_id: circle_id.clone(),
        },
        None => ScopeRef::Realm {
            realm_id: relation.realm_id.clone(),
        },
    };
    references_visible(
        conn,
        &relation.realm_id,
        &scope,
        [&relation.from_ref, &relation.to_ref],
        caller,
    )
    .await
}

async fn references_visible(
    conn: &mut AsyncPgConnection,
    realm_id: &RealmId,
    scope: &ScopeRef,
    endpoints: [&RelationEndpoint; 2],
    caller: &ActorId,
) -> PersistenceResult<bool> {
    if !scope_visible(conn, scope, caller).await? {
        return Ok(false);
    }
    for endpoint in endpoints {
        if !endpoint_visible(conn, realm_id, endpoint, caller).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) async fn event_visible_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    caller: &ActorId,
) -> PersistenceResult<bool> {
    use arkret_models_collaboration::events_payloads::relation::{
        RelationCreatePayload, RelationTombstonePayload, RelationUpdatePayload,
    };
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let definition = if event.kind == arkret_wire::EventKind::RelationCreate {
        let payload: RelationCreatePayload =
            serde_json::from_value(payload).map_err(PersistenceError::database)?;
        payload.relation
    } else {
        let (id, domain) = match event.kind {
            arkret_wire::EventKind::RelationUpdate => {
                let payload: RelationUpdatePayload =
                    serde_json::from_value(payload).map_err(PersistenceError::database)?;
                (payload.relation_id, payload.primary_conflict_domain)
            }
            arkret_wire::EventKind::RelationTombstone => {
                let payload: RelationTombstonePayload =
                    serde_json::from_value(payload).map_err(PersistenceError::database)?;
                (payload.relation_id, payload.primary_conflict_domain)
            }
            _ => return Ok(false),
        };
        let create_id =
            EventId::from_token_bytes(id.token_bytes()).map_err(PersistenceError::database)?;
        let token = crate::ids::parse_event_id(create_id.as_str()).ok_or_else(|| {
            PersistenceError::SchemaViolation(
                "Relation create identity is not canonical".to_owned(),
            )
        })?;
        let Some(row) = sql_query(
            "SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
             WHERE e.id=$1 AND e.realm_id=$2 AND e.kind='ak.relation.create' AND e.state='committed'",
        ).bind::<diesel::sql_types::Binary, _>(token.to_vec()).bind::<Text, _>(event.realm_id.as_str())
            .get_result::<EventRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        else { return Ok(false); };
        let create: arkret_wire::Event =
            serde_json::from_value(row.envelope).map_err(PersistenceError::database)?;
        if create.event_id != create_id || create.realm_id != event.realm_id {
            return Err(PersistenceError::Database(
                "Relation history names another create".to_owned(),
            ));
        }
        let payload: RelationCreatePayload = serde_json::from_value(
            serde_json::to_value(create.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
        domain
            .validate_for_definition(&payload.relation)
            .map_err(PersistenceError::database)?;
        payload.relation
    };
    references_visible(
        conn,
        &event.realm_id,
        &event.scope_ref,
        [&definition.from_ref, &definition.to_ref],
        caller,
    )
    .await
}

async fn endpoint_visible(
    conn: &mut AsyncPgConnection,
    source_realm: &RealmId,
    endpoint: &RelationEndpoint,
    caller: &ActorId,
) -> PersistenceResult<bool> {
    let reference = match endpoint {
        RelationEndpoint::Actor(actor) => {
            return Ok(actor == caller
                || crate::authority_commit::accepted_current_member_joined_in_connection(
                    conn,
                    source_realm,
                    actor,
                )
                .await?);
        }
        RelationEndpoint::Object(reference) => reference,
    };
    if let Ok(realm_id) = RealmId::new(reference) {
        return scope_visible(conn, &ScopeRef::Realm { realm_id }, caller).await;
    }
    let query = if arkret_wire::StrandId::new(reference).is_ok() {
        Some(
            "SELECT o.realm_id,o.value,c.stream_ref AS source_stream_ref FROM strand_current_states o \
              LEFT JOIN realm_commits c ON c.realm_id=o.realm_id AND c.commit_id=o.current_commit_id \
              AND c.stream_position=o.current_stream_position WHERE o.strand_id=$1",
        )
    } else if arkret_wire::SpaceId::new(reference).is_ok() {
        Some(
            "SELECT o.realm_id,o.value,c.stream_ref AS source_stream_ref FROM space_current_states o \
              LEFT JOIN realm_commits c ON c.realm_id=o.realm_id AND c.commit_id=o.current_commit_id \
              AND c.stream_position=o.current_stream_position WHERE o.space_id=$1",
        )
    } else {
        None
    };
    if let Some(query) = query {
        let Some(row) = sql_query(query)
            .bind::<Text, _>(reference)
            .get_result::<ObjectRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
        else {
            return Ok(false);
        };
        let realm_id = RealmId::new(row.realm_id).map_err(PersistenceError::database)?;
        let (id, home, circle) = if arkret_wire::StrandId::new(reference).is_ok() {
            let object: arkret_models_collaboration::objects::strand::Strand =
                serde_json::from_value(row.value).map_err(PersistenceError::database)?;
            if object.schema != arkret_wire::SchemaId::STRAND_V1 {
                return Err(PersistenceError::Database(
                    "Relation Strand endpoint has another schema".to_owned(),
                ));
            }
            (
                object.id.map(|id| id.to_string()),
                object.realm_id,
                object.scope_circle_id,
            )
        } else {
            let object: arkret_models_collaboration::objects::space::Space =
                serde_json::from_value(row.value).map_err(PersistenceError::database)?;
            object.validate().map_err(PersistenceError::database)?;
            if object.schema != arkret_wire::SchemaId::SPACE_V1 {
                return Err(PersistenceError::Database(
                    "Relation Space endpoint has another schema".to_owned(),
                ));
            }
            (
                object.id.map(|id| id.to_string()),
                object.realm_id,
                object.scope_circle_id,
            )
        };
        if id.as_deref() != Some(reference.as_str()) || home != realm_id {
            return Err(PersistenceError::Database(
                "Relation endpoint current differs from its native identity".to_owned(),
            ));
        }
        let scope = match circle {
            Some(circle_id) => ScopeRef::Circle {
                realm_id,
                circle_id,
            },
            None => ScopeRef::Realm { realm_id },
        };
        let covering: CommitStreamRef =
            serde_json::from_value(row.source_stream_ref.ok_or_else(|| {
                PersistenceError::Database(
                    "Relation endpoint has no exact covering Commit".to_owned(),
                )
            })?)
            .map_err(PersistenceError::database)?;
        if covering
            != CommitStreamRef::from_scope(&scope, None).map_err(PersistenceError::database)?
        {
            return Err(PersistenceError::Database(
                "Relation endpoint scope differs from its covering Commit".to_owned(),
            ));
        }
        return scope_visible(conn, &scope, caller).await;
    }
    let event_id = if let Ok(message_id) = arkret_wire::MessageId::new(reference) {
        Some(message_id.event_id())
    } else {
        EventId::new(reference).ok()
    };
    let Some(event_id) = event_id else {
        // No target-side reference evidence: source membership never makes an
        // unknown, remote or unproved object reference disclosable.
        return Ok(false);
    };
    let token = crate::ids::parse_event_id(event_id.as_str()).ok_or_else(|| {
        PersistenceError::SchemaViolation("Relation Event endpoint is not canonical".to_owned())
    })?;
    let Some(row) = sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.state='committed' \
         AND NOT EXISTS(SELECT 1 FROM retention_tombstones t WHERE t.event_id=e.id) \
         AND NOT EXISTS(SELECT 1 FROM object_redaction_current_states r WHERE r.realm_id=e.realm_id \
             AND r.target_ref IN ($2,e.envelope->>'event_id'))",
    ).bind::<diesel::sql_types::Binary, _>(token.to_vec()).bind::<Text, _>(reference)
        .get_result::<EventRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
    else { return Ok(false); };
    let event: arkret_wire::Event =
        serde_json::from_value(row.envelope).map_err(PersistenceError::database)?;
    let commit: arkret_wire::RealmCommit =
        serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
    if event.event_id != event_id
        || commit.event_ref != event_id
        || CommitStreamRef::from_scope(&event.scope_ref, None)
            .map_err(PersistenceError::database)?
            != commit.stream_ref
    {
        return Err(PersistenceError::Database(
            "Relation Event endpoint differs from its covering Commit".to_owned(),
        ));
    }
    let floor = match &commit.stream_ref {
        CommitStreamRef::Realm { realm_id } => {
            crate::account_stream_scan::caller_realm_floor_in_connection(conn, realm_id, caller)
                .await?
        }
        CommitStreamRef::Circle {
            realm_id,
            circle_id,
        } => {
            crate::account_stream_scan::caller_circle_floor_in_connection(
                conn, realm_id, circle_id, caller,
            )
            .await?
        }
        _ => None,
    };
    if floor.is_none_or(|floor| commit.stream_position < floor.oldest_position) {
        return Ok(false);
    }
    Box::pin(
        crate::committed_disclosure::full_event_for_member_in_connection(
            conn,
            &arkret_wire::CommittedEventFullView { event, commit },
            caller,
            chrono::Utc::now(),
        ),
    )
    .await
}
