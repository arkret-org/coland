//! Same-cut Sidecar genesis reservation and durable current. The public
//! ensure route remains closed until create and attach can commit as one unit.

use arkret_models_collaboration::events_payloads::sidecar::SidecarContextAttachPayload;
use arkret_models_collaboration::sidecar_operations::SidecarContextRef;
use arkret_wire::{CommitStreamRef, Event, EventKind, RealmCommit, ScopeRef, SidecarId};
use coland_storage::{ConflictCode, PersistenceError, PersistenceResult};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::{Value, json};

#[derive(diesel::QueryableByName)]
struct ExistingCreate {
    #[diesel(sql_type = Text)]
    create_event_id: String,
}

#[derive(diesel::QueryableByName)]
struct SidecarOwner {
    #[diesel(sql_type = Jsonb)]
    controller_account_id: Value,
    #[diesel(sql_type = Text)]
    create_event_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct ContextHead {
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Text)]
    attach_event_id: String,
}

#[derive(diesel::QueryableByName)]
struct SourceValue {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn invalid(detail: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_owned())
}

fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", ConflictCode::CapabilityDenied))
}

fn conflict(code: ConflictCode, detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{code}: {detail}"))
}

fn context_digest(context: &SidecarContextRef) -> PersistenceResult<String> {
    arkret_canonical::canonical_sha256(context).map_err(PersistenceError::database)
}

async fn source_value(
    conn: &mut AsyncPgConnection,
    event: &Event,
    context: &SidecarContextRef,
) -> PersistenceResult<Option<Value>> {
    let value = match context {
        SidecarContextRef::Strand { strand_id } => sql_query(
            "SELECT value FROM strand_current_states WHERE realm_id=$1 AND strand_id=$2 FOR SHARE",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<Text, _>(strand_id.as_str())
        .get_result::<SourceValue>(conn)
        .await
        .optional(),
        SidecarContextRef::Relation { relation_id } => sql_query(
            "SELECT value FROM relation_current_states \
             WHERE realm_id=$1 AND relation_id=$2 AND state='active' LIMIT 1 FOR SHARE",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<Text, _>(relation_id.as_str())
        .get_result::<SourceValue>(conn)
        .await
        .optional(),
    }
    .map_err(PersistenceError::database)?;
    Ok(value.map(|row| row.value))
}

async fn admit_context_attach(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    let payload: SidecarContextAttachPayload = serde_json::from_value(json!(&event.payload))
        .map_err(|_| invalid("Sidecar context payload is invalid"))?;
    payload
        .validate()
        .map_err(|_| invalid("Sidecar context version/predecessor is invalid"))?;
    if event.scope_ref
        != (ScopeRef::Sidecar {
            realm_id: event.realm_id.clone(),
            sidecar_id: payload.sidecar_id.clone(),
        })
        || commit.stream_ref
            != (CommitStreamRef::Sidecar {
                realm_id: event.realm_id.clone(),
                sidecar_id: payload.sidecar_id.clone(),
            })
        || event.executed_by.is_some()
        || event.applet_id.is_some()
    {
        return Err(invalid(
            "Sidecar context needs its native stream and direct actor",
        ));
    }
    let Some(account) = event.actor_id.as_account_id() else {
        return Err(denied(
            "Sidecar context actor is not its controller Account",
        ));
    };
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    if crate::member_state_admission::locked_membership(conn, &event.realm_id, &event.actor_id)
        .await?
        != "join"
    {
        return Err(denied("Sidecar controller is not a current Realm member"));
    }
    let owner = sql_query(
        "SELECT controller_account_id,create_event_id,value FROM sidecar_current_states \
         WHERE realm_id=$1 AND sidecar_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.sidecar_id.as_str())
    .get_result::<SidecarOwner>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| denied("Sidecar controller or scope is unavailable"))?;
    if owner.controller_account_id
        != serde_json::to_value(account).map_err(PersistenceError::database)?
        || owner.value["state"] != "active"
    {
        return Err(denied("Sidecar controller or scope is unavailable"));
    }
    let after: Vec<_> = event
        .semantic_refs
        .iter()
        .filter(|reference| reference.role == "after")
        .collect();
    if after.len() != 1 || !after[0].critical || after[0].id != owner.create_event_id {
        return Err(invalid("Sidecar context must cite its exact genesis Event"));
    }
    let source = source_value(conn, event, &payload.source_context_ref)
        .await?
        .ok_or_else(|| {
            conflict(
                ConflictCode::FailedPrecondition,
                "source context is unavailable",
            )
        })?;
    // A Circle-scoped source needs the Circle ACL cut, which this unit does
    // not yet possess. Realm-default sources are visible to joined members.
    if source
        .get("scope_circle_id")
        .is_some_and(|scope| !scope.is_null())
    {
        return Err(conflict(
            ConflictCode::UnsupportedFeature,
            "Circle-scoped Sidecar source needs its scope authorization cut",
        ));
    }
    // Exact accepted retries must survive a missing HTTP receipt. They still
    // pass through the authority writer's duplicate check and do not project
    // current again; matching only the payload/version would admit stale writes.
    if crate::authority_commit::is_exact_accepted_event_replay(conn, event, commit).await? {
        return Ok(());
    }
    let digest = context_digest(&payload.source_context_ref)?;
    let head = sql_query(
        "SELECT version,attach_event_id FROM sidecar_context_current_states \
         WHERE sidecar_id=$1 AND context_ref_digest=$2 FOR UPDATE",
    )
    .bind::<Text, _>(payload.sidecar_id.as_str())
    .bind::<Text, _>(&digest)
    .get_result::<ContextHead>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    match head {
        None if payload.version == 1 && payload.predecessor_event_ref.is_none() => Ok(()),
        Some(head)
            if i64::try_from(payload.version).ok() == head.version.checked_add(1)
                && payload.predecessor_event_ref.as_ref().map(|id| id.as_str())
                    == Some(head.attach_event_id.as_str()) =>
        {
            Ok(())
        }
        _ => Err(conflict(
            ConflictCode::CasConflict,
            "Sidecar context predecessor or version is stale",
        )),
    }
}

#[derive(diesel::QueryableByName)]
struct PreparedContextRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Jsonb)]
    accepted_payload: Value,
    #[diesel(sql_type = Text)]
    attach_event_id: String,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

/// The draft records a read cut, never a reservation of the CAS head. The
/// existing admission transaction rechecks it under its Realm/context locks.
pub(crate) async fn prepare_context_current(
    pool: &crate::PgPool,
    realm: &arkret_wire::RealmId,
    controller: &arkret_wire::AccountId,
    context: &SidecarContextRef,
) -> PersistenceResult<
    Option<(
        arkret_wire::EventId,
        Option<coland_storage::AgentSidecarContextRecord>,
    )>,
> {
    use diesel_async::AsyncConnection as _;
    let mut conn = crate::pg_conn(pool).await?;
    conn.transaction::<_, crate::PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY").execute(&mut *conn).await?;
        let realm_stream = serde_json::to_value(CommitStreamRef::Realm { realm_id: realm.clone() })
            .map_err(PersistenceError::database)?;
        let actor = arkret_wire::ActorId::account(controller.clone());
        let basis = sql_query("SELECT EXISTS(SELECT 1 FROM realm_authorities a \
            JOIN member_state_current_states m ON m.realm_id=a.realm_id \
            JOIN realm_commits c ON c.realm_id=m.realm_id AND c.commit_id=m.current_commit_id AND c.stream_position=m.current_stream_position \
            JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
            WHERE a.realm_id=$1 AND a.service_id=$2 AND m.member_id=$3 AND m.membership='join' AND m.value->>'membership'='join' AND c.stream_ref=$4) AS present")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(controller.station_id.as_str())
            .bind::<Text,_>(actor.to_string()).bind::<Jsonb,_>(&realm_stream)
            .get_result::<crate::query_rows::ExistsRow>(&mut *conn).await?.present;
        if !basis { return Err(denied("authoritative Sidecar prepare membership or tenure is unavailable").into()) }
        let controller_json = serde_json::to_value(controller).map_err(PersistenceError::database)?;
        // Only genuine absence at the unique native singleton key opens new.
        let exists = sql_query("SELECT EXISTS(SELECT 1 FROM sidecar_current_states WHERE realm_id=$1 AND controller_account_id=$2) AS present")
            .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(&controller_json)
            .get_result::<crate::query_rows::ExistsRow>(&mut *conn).await?.present;
        if !exists { return Ok(None) }
        let owner = sql_query("SELECT s.controller_account_id,s.create_event_id,s.value FROM sidecar_current_states s \
            JOIN realm_commits c ON c.realm_id=s.realm_id AND c.commit_id=s.current_commit_id AND c.stream_position=s.current_stream_position AND c.stream_ref=s.source_stream_ref \
            JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' AND e.kind='ak.sidecar.create' \
            WHERE s.realm_id=$1 AND s.controller_account_id=$2 AND s.value->>'state'='active' \
            AND c.stream_ref=$3 AND c.commit_json->>'event_ref'=s.create_event_id AND e.envelope->>'event_id'=s.create_event_id \
            AND e.envelope->'actor_id'=$4 AND s.sidecar_id='ak:sidecar:' || substring(s.create_event_id from 10)")
            .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(&controller_json).bind::<Jsonb,_>(&realm_stream)
            .bind::<Jsonb,_>(serde_json::to_value(&actor).map_err(PersistenceError::database)?)
            .get_result::<SidecarOwner>(&mut *conn).await.optional()?
            .ok_or_else(|| denied("held Sidecar singleton is not an active accepted controller resource"))?;
        let genesis = arkret_wire::EventId::new(owner.create_event_id).map_err(PersistenceError::database)?;
        let sidecar = SidecarId::from_event_id(&genesis);
        let sidecar_stream = serde_json::to_value(CommitStreamRef::Sidecar { realm_id: realm.clone(), sidecar_id: sidecar.clone() }).map_err(PersistenceError::database)?;
        let digest = context_digest(context)?;
        // A missing canonical join is unavailable evidence, not a new context.
        let row = sql_query("SELECT r.value,e.envelope->'payload' AS accepted_payload,r.attach_event_id,r.version,(e.envelope->>'created_at')::timestamptz AS created_at \
            FROM sidecar_context_current_states r \
            JOIN realm_commits c ON c.realm_id=r.realm_id AND c.commit_id=r.current_commit_id AND c.stream_position=r.current_stream_position AND c.stream_ref=r.source_stream_ref AND c.commit_json->>'event_ref'=r.attach_event_id \
            JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' AND e.kind='ak.sidecar.context.attach' AND e.envelope->>'event_id'=r.attach_event_id \
            WHERE r.realm_id=$1 AND r.sidecar_id=$2 AND r.context_ref_digest=$3 AND c.stream_ref=$4 AND e.envelope->'scope_ref'=$4 AND e.envelope->'actor_id'=$5")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(sidecar.as_str()).bind::<Text,_>(&digest)
            .bind::<Jsonb,_>(&sidecar_stream).bind::<Jsonb,_>(serde_json::to_value(&actor).map_err(PersistenceError::database)?)
            .get_result::<PreparedContextRow>(&mut *conn).await.optional()?;
        let Some(row) = row else {
            let exists = sql_query("SELECT EXISTS(SELECT 1 FROM sidecar_context_current_states WHERE realm_id=$1 AND sidecar_id=$2 AND context_ref_digest=$3) AS present")
                .bind::<Text,_>(realm.as_str()).bind::<Text,_>(sidecar.as_str()).bind::<Text,_>(&digest)
                .get_result::<crate::query_rows::ExistsRow>(&mut *conn).await?.present;
            return if exists { Err(invalid("held Sidecar context lacks accepted provenance").into()) } else { Ok(Some((genesis, None))) };
        };
        let payload: SidecarContextAttachPayload = serde_json::from_value(row.value.clone()).map_err(PersistenceError::database)?;
        payload.validate().map_err(PersistenceError::database)?;
        if payload.sidecar_id != sidecar || payload.source_context_ref != *context
            || i64::try_from(payload.version).ok() != Some(row.version) || row.value != row.accepted_payload {
            return Err(invalid("Sidecar context current differs from its accepted source").into());
        }
        Ok(Some((genesis, Some(coland_storage::AgentSidecarContextRecord {
            sidecar_id: sidecar.to_string(), normalized_context_ref_digest: digest,
            normalized_context_ref: serde_json::to_value(context).map_err(PersistenceError::database)?,
            version: row.version, predecessor_event_ref: payload.predecessor_event_ref.map(|id| id.to_string()),
            attach_event_ref: row.attach_event_id, created_at: row.created_at,
        }))))
    }).await.map_err(crate::PgTransactionError::into_persistence)
}

pub(crate) async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind == EventKind::SidecarContextAttach {
        return admit_context_attach(conn, event, commit).await;
    }
    if event.kind != EventKind::SidecarCreate {
        return Ok(());
    }
    if event.scope_ref
        != (ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        })
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || !event.payload.is_empty()
        || event.executed_by.is_some()
        || event.applet_id.is_some()
    {
        return Err(invalid(
            "Sidecar genesis needs its empty Realm-stream account Event",
        ));
    }
    let Some(controller) = event.actor_id.as_account_id() else {
        return Err(denied("sidecar_create_denied"));
    };
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    if crate::member_state_admission::locked_membership(conn, &event.realm_id, &event.actor_id)
        .await?
        != "join"
    {
        return Err(denied("sidecar_create_denied"));
    }
    let existing = sql_query(
        "SELECT create_event_id FROM sidecar_current_states \
         WHERE realm_id=$1 AND controller_account_id=$2 FOR SHARE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(controller).map_err(PersistenceError::database)?)
    .get_result::<ExistingCreate>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if existing.is_some_and(|row| row.create_event_id != event.event_id.as_str()) {
        return Err(PersistenceError::Conflict(format!(
            "{}: Sidecar singleton already reserved",
            ConflictCode::FailedPrecondition
        )));
    }
    Ok(())
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind == EventKind::SidecarContextAttach {
        let payload: SidecarContextAttachPayload = serde_json::from_value(json!(&event.payload))
            .map_err(|_| invalid("Sidecar context payload is invalid"))?;
        let position = i64::try_from(commit.stream_position)
            .map_err(|_| invalid("Sidecar stream position exceeds storage"))?;
        let version = i64::try_from(payload.version)
            .map_err(|_| invalid("Sidecar context version exceeds storage"))?;
        let digest = context_digest(&payload.source_context_ref)?;
        let context = serde_json::to_value(&payload.source_context_ref)
            .map_err(PersistenceError::database)?;
        let value = serde_json::to_value(&payload).map_err(PersistenceError::database)?;
        let written = sql_query(
            "INSERT INTO sidecar_context_current_states \
             (realm_id,sidecar_id,context_ref_digest,context_ref,version,predecessor_event_ref,attach_event_id,current_commit_id,current_stream_position,source_stream_ref,value,updated_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) \
             ON CONFLICT(sidecar_id,context_ref_digest) DO UPDATE SET \
             version=EXCLUDED.version,predecessor_event_ref=EXCLUDED.predecessor_event_ref, \
             attach_event_id=EXCLUDED.attach_event_id,current_commit_id=EXCLUDED.current_commit_id, \
             current_stream_position=EXCLUDED.current_stream_position,source_stream_ref=EXCLUDED.source_stream_ref, \
             value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
             WHERE sidecar_context_current_states.version + 1 = EXCLUDED.version \
             AND sidecar_context_current_states.attach_event_id = EXCLUDED.predecessor_event_ref",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<Text, _>(payload.sidecar_id.as_str())
        .bind::<Text, _>(digest)
        .bind::<Jsonb, _>(context)
        .bind::<BigInt, _>(version)
        .bind::<diesel::sql_types::Nullable<Text>, _>(payload.predecessor_event_ref.as_ref().map(|id| id.as_str()))
        .bind::<Text, _>(event.event_id.as_str())
        .bind::<Text, _>(commit.commit_id.as_str())
        .bind::<BigInt, _>(position)
        .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
        .bind::<Jsonb, _>(value)
        .bind::<Timestamptz, _>(commit.committed_at)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
        if written != 1 {
            return Err(conflict(
                ConflictCode::CasConflict,
                "Sidecar context predecessor or version is stale",
            ));
        }
        return Ok(());
    }
    if event.kind != EventKind::SidecarCreate {
        return Ok(());
    }
    let controller = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| denied("sidecar_create_denied"))?;
    let id = SidecarId::from_event_id(&event.event_id);
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| invalid("Sidecar stream position exceeds storage"))?;
    let value: Value = json!({
        "id": id,
        "schema": arkret_wire::SchemaId::AGENT_SIDECAR_V1,
        "realm_id": event.realm_id,
        "controller_account_id": controller,
        "state": "active",
        "created_at": arkret_canonical::format_timestamp_canonical(event.created_at),
        "updated_at": arkret_canonical::format_timestamp_canonical(event.created_at),
    });
    sql_query(
        "INSERT INTO sidecar_current_states \
         (realm_id,sidecar_id,controller_account_id,create_event_id,current_commit_id,current_stream_position,source_stream_ref,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(controller).map_err(PersistenceError::database)?)
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}
