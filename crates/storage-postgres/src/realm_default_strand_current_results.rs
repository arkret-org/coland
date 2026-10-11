//! The Realm's single default Strand pointer, written at its covering Commit.

use coland_storage::{PersistenceError, PersistenceResult};
use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

#[derive(diesel::QueryableByName)]
struct CurrentRow {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct CommitIdRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
}

#[derive(diesel::QueryableByName)]
struct TargetRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    present: bool,
}

fn conflict(detail: &'static str) -> PersistenceError {
    PersistenceError::Conflict(detail.to_owned())
}

#[derive(diesel::QueryableByName)]
struct ProvedCurrentRow {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    proved: bool,
}

pub(crate) async fn read_current(
    pool: &crate::PgPool,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Option<arkret_wire::TypedCurrentRow>> {
    let mut conn = crate::pg_conn(pool).await?;
    let source = crate::object_projection_reads::current_source_sql(
        "r",
        "jsonb_build_object('kind','realm_set_default_strand')",
    );
    let row = diesel::sql_query(format!(
        "SELECT r.current_commit_id,r.current_stream_position,r.value, \
         COALESCE({source}=jsonb_build_object('kind','realm','realm_id',r.realm_id),false) AS proved \
         FROM realm_set_default_strand_current_results r WHERE r.realm_id=$1"
    ))
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<ProvedCurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    row.map(|row| {
        if !row.proved {
            return Err(PersistenceError::Internal(
                "default Strand current has no accepted source cut".to_owned(),
            ));
        }
        Ok(arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::RealmSetDefaultStrand,
            source_stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            revision: arkret_wire::CurrentRevision {
                commit_id: arkret_wire::RealmCommitId::new(row.current_commit_id)
                    .map_err(PersistenceError::database)?,
                stream_position: u64::try_from(row.current_stream_position)
                    .map_err(PersistenceError::database)?,
            },
            value: row.value,
        })
    })
    .transpose()
}

/// The caller holds the Realm authority row lock through the encompassing
/// Event/Commit UoW. All current pointer checks and the write use this same
/// transaction, so a stale in-memory Realm projection cannot select a winner.
pub(crate) async fn commit_realm_default_strand_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmSetDefaultStrand {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if commit.stream_ref
        != (arkret_wire::CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        })
    {
        return Err(conflict("default Strand requires the Realm commit stream"));
    }
    let payload: arkret_models_collaboration::events_payloads::strand::RealmSetDefaultStrandPayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if payload.realm_id != event.realm_id {
        return Err(conflict("default Strand payload names a different Realm"));
    }
    let prior = diesel::sql_query(
        "SELECT c.commit_id,c.stream_position FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND c.stream_ref=$2 AND c.stream_position<$3 \
           AND e.kind='ak.realm.set_default_strand' AND e.state='committed' \
         ORDER BY c.stream_position DESC LIMIT 1",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
    .bind::<BigInt, _>(i64::try_from(commit.stream_position).map_err(|_| conflict("invalid default Strand stream position"))?)
    .get_result::<CommitIdRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let current = diesel::sql_query(
        "SELECT current_commit_id,current_stream_position,value \
         FROM realm_set_default_strand_current_results WHERE realm_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<CurrentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if prior
        .as_ref()
        .map(|row| (row.commit_id.as_str(), row.stream_position))
        != current
            .as_ref()
            .map(|row| (row.current_commit_id.as_str(), row.current_stream_position))
    {
        return Err(conflict(
            "default Strand current result is missing or stale",
        ));
    }
    if let Some(current) = current.as_ref()
        && current.current_stream_position
            >= i64::try_from(commit.stream_position)
                .map_err(|_| conflict("invalid default Strand stream position"))?
    {
        return Err(conflict(
            "default Strand current revision does not precede Event",
        ));
    }
    let existing = match current.as_ref() {
        None => None,
        Some(row) => {
            let object = row.value.as_object().ok_or_else(|| {
                PersistenceError::Internal(
                    "stored default Strand current value is malformed".to_owned(),
                )
            })?;
            if object.len() != 1 {
                return Err(PersistenceError::Internal(
                    "stored default Strand current value has extra members".to_owned(),
                ));
            }
            Some(
                object
                    .get("default_strand_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        PersistenceError::Internal(
                            "stored default Strand pointer is malformed".to_owned(),
                        )
                    })?,
            )
        }
    };
    if existing
        != payload
            .expected_default_strand_id
            .as_ref()
            .map(arkret_wire::StrandId::as_str)
    {
        return Err(conflict("default Strand expected pointer CAS mismatch"));
    }
    let target = diesel::sql_query(
        "SELECT s.value,s.current_stream_position FROM strand_current_results s \
         JOIN realm_commits c ON c.commit_id=s.current_commit_id \
         WHERE s.realm_id=$1 AND s.strand_id=$2 \
           AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=s.realm_id \
         FOR SHARE OF s",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.strand_id.as_str())
    .get_result::<TargetRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| conflict("default Strand target has no confirmed current result"))?;
    if target.value.get("state") != Some(&Value::String("active".to_owned())) {
        return Err(conflict("default Strand target is not active"));
    }
    // Unsupported structural or terminal writes cannot be inferred from
    // this current row. Materialized lifecycle and progress writes can.
    let changed = diesel::sql_query(
        "SELECT EXISTS ( \
           SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
           WHERE e.realm_id=$1 AND e.state='committed' \
             AND c.stream_position>$2 \
             AND (e.kind LIKE 'ak.strand.%' OR e.kind='ak.redaction') \
             AND e.kind NOT IN ('ak.strand.create','ak.strand.update','ak.strand.archive','ak.strand.restore','ak.strand.stage.set','ak.strand.watch.set','ak.strand.move','ak.strand.reorder') \
         ) AS present",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<BigInt, _>(target.current_stream_position)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed.present {
        return Err(conflict(
            "default Strand target has an unprojected successor",
        ));
    }
    let value = serde_json::json!({"default_strand_id":payload.strand_id});
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| conflict("invalid default Strand stream position"))?;
    diesel::sql_query(
        "INSERT INTO realm_set_default_strand_current_results \
         (realm_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5) \
         ON CONFLICT(realm_id) DO UPDATE SET \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}
