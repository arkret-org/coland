use arkret_models_collaboration::objects::relation::{Relation, RelationPrimaryConflictDomain};
use arkret_wire::{CurrentRevision, RealmCommitId, RelationState};

use super::{
    AsyncPgConnection, BigInt, Jsonb, OptionalExtension, PersistenceError, PersistenceResult,
    PgPool, QueryableByName, RelationCurrentResultRecord, RelationCurrentResultStore, RunQueryDsl,
    Text, async_trait, pg_conn, sql_query,
};

pub struct PgRelationCurrentResultStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct RelationCurrentResultReadRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    domain_key: String,
    #[diesel(sql_type = Jsonb)]
    domain: serde_json::Value,
    #[diesel(sql_type = Text)]
    relation_id: String,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

fn corrupt(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::Database(detail.into())
}

fn decode_row(row: RelationCurrentResultReadRow) -> PersistenceResult<RelationCurrentResultRecord> {
    let realm_id = row
        .realm_id
        .parse::<arkret_wire::RealmId>()
        .map_err(|error| corrupt(format!("stored Relation Realm id is invalid: {error}")))?;
    let domain = serde_json::from_value::<RelationPrimaryConflictDomain>(row.domain)
        .map_err(|error| corrupt(format!("stored Relation domain is invalid: {error}")))?;
    let canonical_domain = arkret_canonical::canonical_json_string(&domain).map_err(|error| {
        corrupt(format!(
            "stored Relation domain cannot canonicalize: {error}"
        ))
    })?;
    if canonical_domain != row.domain_key {
        return Err(corrupt(
            "stored Relation domain key does not match its domain",
        ));
    }
    let relation = serde_json::from_value::<Relation>(row.value)
        .map_err(|error| corrupt(format!("stored Relation current value is invalid: {error}")))?;
    if relation
        .validate_current_for_domain(&realm_id, &domain)
        .is_err()
        || relation.id.as_ref().map(|id| id.as_str()) != Some(row.relation_id.as_str())
    {
        return Err(corrupt(
            "stored Relation current value does not match its row identity",
        ));
    }
    let state_matches = matches!(
        (row.state.as_str(), relation.state.as_ref()),
        ("active", Some(RelationState::Active)) | ("tombstoned", Some(RelationState::Tombstoned))
    );
    if !state_matches {
        return Err(corrupt(
            "stored Relation lifecycle does not match its current row",
        ));
    }
    let stream_position = u64::try_from(row.current_stream_position)
        .map_err(|_| corrupt("stored Relation stream position is negative"))?;
    let commit_id = row
        .current_commit_id
        .parse::<RealmCommitId>()
        .map_err(|error| corrupt(format!("stored Relation Commit id is invalid: {error}")))?;
    Ok(RelationCurrentResultRecord {
        realm_id,
        domain_key: row.domain_key,
        primary_conflict_domain: domain,
        relation,
        revision: CurrentRevision {
            commit_id,
            stream_position,
        },
    })
}

#[derive(QueryableByName)]
struct RelationSnapshotReadRow {
    #[diesel(embed)]
    current: RelationCurrentResultReadRow,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    source_stream_ref: Option<serde_json::Value>,
}

pub(crate) async fn snapshot_rows_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Vec<arkret_wire::TypedCurrentRow>> {
    let rows = sql_query(
        "SELECT result.*, covering.stream_ref AS source_stream_ref \
         FROM relation_current_results result LEFT JOIN realm_commits covering \
           ON covering.realm_id=result.realm_id \
          AND covering.commit_id=result.current_commit_id \
          AND covering.stream_position=result.current_stream_position \
         WHERE result.realm_id=$1 ORDER BY result.domain_key",
    )
    .bind::<Text, _>(realm_id.as_str())
    .load::<RelationSnapshotReadRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    rows.into_iter()
        .map(|row| {
            let record = decode_row(row.current)?;
            let source_stream_ref = serde_json::from_value::<arkret_wire::CommitStreamRef>(
                row.source_stream_ref
                    .ok_or_else(|| corrupt("Relation current has no exact covering Commit"))?,
            )
            .map_err(PersistenceError::database)?;
            let expected = match record.relation.scope_circle_id.as_ref() {
                Some(circle_id) => arkret_wire::CommitStreamRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id: circle_id.clone(),
                },
                None => arkret_wire::CommitStreamRef::Realm {
                    realm_id: realm_id.clone(),
                },
            };
            if source_stream_ref != expected {
                return Err(corrupt(
                    "Relation current source differs from its value scope",
                ));
            }
            Ok(arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::Relation {
                    primary_conflict_domain: record.primary_conflict_domain,
                },
                source_stream_ref,
                revision: record.revision,
                value: serde_json::to_value(record.relation).map_err(PersistenceError::database)?,
            })
        })
        .collect()
}

#[derive(QueryableByName)]
struct EndpointHomeRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    scope_circle_id: Option<String>,
}

fn precondition(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "{}: {detail}",
        coland_storage::ConflictCode::FailedPrecondition
    ))
}

/// The Circle an `ak.relation.*` Event is signed in, `None` for Realm scope.
fn signed_scope_circle(event: &arkret_wire::Event) -> Option<&arkret_wire::CircleId> {
    match &event.scope_ref {
        arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id),
        _ => None,
    }
}

/// Authority admission of one `ak.relation.create` / `.update` /
/// `.tombstone` at the accepting cut, before the domain row is read.
///
/// `relation.md` section 4.3: Relation writes are authorized in the source
/// Realm. The Event commits on the exact stream its signed scope names; a
/// Circle-scoped fact additionally needs an active Circle author at this cut.
pub(crate) async fn authorize_relation_write_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    let expected_stream =
        arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if commit.event_ref != event.event_id || commit.stream_ref != expected_stream {
        return Err(precondition(
            "Relation write differs from its accepting source stream",
        ));
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
        conn, event, commit, prepared,
    )
    .await?;
    if signed_scope_circle(event).is_some() {
        crate::circle_current_results::require_active_author_in_connection(conn, event, commit)
            .await?;
    }
    Ok(())
}

/// The Realm and Circle scope of an object endpoint this Station holds a
/// current value for. Strand and Space rows carry their own scope; a Message
/// endpoint has only a Realm here.
async fn endpoint_home(
    conn: &mut AsyncPgConnection,
    endpoint: &str,
) -> PersistenceResult<Option<EndpointHomeRow>> {
    let query = if endpoint.starts_with("ak:strand:") {
        "SELECT realm_id,value->>'scope_circle_id' AS scope_circle_id \
         FROM strand_current_results WHERE strand_id=$1 ORDER BY realm_id LIMIT 1"
    } else if endpoint.starts_with("ak:space:") {
        "SELECT realm_id,value->>'scope_circle_id' AS scope_circle_id \
         FROM space_current_results WHERE space_id=$1 ORDER BY realm_id LIMIT 1"
    } else if endpoint.starts_with("ak:message:") {
        "SELECT realm_id,NULL::text AS scope_circle_id \
         FROM message_revision_current_results WHERE message_id=$1 ORDER BY realm_id LIMIT 1"
    } else {
        return Ok(None);
    };
    sql_query(query)
        .bind::<Text, _>(endpoint)
        .get_result::<EndpointHomeRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)
}

/// Scope and endpoint rules of the post-write Relation value.
///
/// - The value's `scope_circle_id` is exactly the Circle the Event is signed in (none for Realm
///   scope), before and after an update, so a write never moves a fact out of the stream that
///   discloses it (`circle.md` section 6).
/// - `confidential_discussion_of` links a private Strand to its public Strand and is committed in
///   that private Strand's Circle (`relation.md` 3.2).
/// - A structural Relation names only objects of its own Realm; any other or unresolved object
///   endpoint is `cross_realm_structural_relation` (`relation.md` section 4.4).
/// - A scoped endpoint floors the Relation's scope: a Relation is never wider than the
///   Circle-scoped Strand or Space it connects.
pub(crate) async fn require_relation_value_scope_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    before: Option<&Relation>,
    after: &Relation,
    created: bool,
) -> PersistenceResult<()> {
    let signed = signed_scope_circle(event);
    for value in before.into_iter().chain(std::iter::once(after)) {
        if value.scope_circle_id.as_ref() != signed {
            return Err(precondition(
                "Relation scope differs from the scope its Event is signed in",
            ));
        }
    }
    if !created {
        return Ok(());
    }
    let relation_kind = after.relation_kind.as_str();
    if relation_kind == "confidential_discussion_of" && signed.is_none() {
        return Err(PersistenceError::SchemaViolation(
            "confidential_discussion_of is committed in its private Strand's Circle".to_owned(),
        ));
    }
    let structural =
        arkret_models_collaboration::objects::relation::relation_kind_is_structural(relation_kind);
    let floored = matches!(
        relation_kind,
        "contains" | "belongs_to" | "confidential_discussion_of" | "assigned_to"
    );
    let mut homes = Vec::new();
    for endpoint in [&after.from_ref, &after.to_ref] {
        let Some(endpoint) = endpoint.as_object_ref() else {
            homes.push(None);
            continue;
        };
        let home = endpoint_home(conn, endpoint).await?;
        if structural
            && home
                .as_ref()
                .is_none_or(|home| home.realm_id != event.realm_id.as_str())
        {
            return Err(PersistenceError::Conflict(format!(
                "{}: structural Relation endpoint {endpoint} is not an object of this Realm",
                coland_storage::ConflictCode::CrossRealmStructuralRelation
            )));
        }
        if floored
            && let Some(home) = home
                .as_ref()
                .filter(|home| home.realm_id == event.realm_id.as_str())
            && let Some(endpoint_circle) = home.scope_circle_id.as_deref()
            && signed.map(arkret_wire::CircleId::as_str) != Some(endpoint_circle)
        {
            return Err(precondition(
                "Relation scope is wider than a Circle-scoped endpoint",
            ));
        }
        homes.push(home);
    }
    if relation_kind == "confidential_discussion_of" {
        fn in_realm<'a>(home: &'a Option<EndpointHomeRow>, realm: &str) -> Option<Option<&'a str>> {
            home.as_ref()
                .filter(|home| home.realm_id == realm)
                .map(|home| home.scope_circle_id.as_deref())
        }
        let realm = event.realm_id.as_str();
        let strands = after
            .from_ref
            .as_object_ref()
            .is_some_and(|from| from.starts_with("ak:strand:"))
            && after
                .to_ref
                .as_object_ref()
                .is_some_and(|to| to.starts_with("ak:strand:"));
        if !strands
            || in_realm(&homes[0], realm) != Some(signed.map(arkret_wire::CircleId::as_str))
            || in_realm(&homes[1], realm) != Some(None)
        {
            return Err(precondition(
                "confidential_discussion_of links a private Strand to its public Strand",
            ));
        }
    }
    Ok(())
}

#[async_trait]
impl RelationCurrentResultStore for PgRelationCurrentResultStore {
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RelationCurrentResultRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let rows = sql_query(
            "SELECT realm_id,domain_key,domain,relation_id,state,current_commit_id,\
             current_stream_position,value FROM relation_current_results \
             ORDER BY realm_id ASC,domain_key ASC",
        )
        .load::<RelationCurrentResultReadRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter().map(decode_row).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_rejects_a_value_whose_lifecycle_disagrees_with_the_row() {
        let row = RelationCurrentResultReadRow {
            realm_id: "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru".to_owned(),
            domain_key: arkret_canonical::canonical_json_string(&serde_json::json!({
                "domain_kind":"tuple",
                "relation_kind":"references",
                "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
                "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-"
            }))
            .unwrap(),
            domain: serde_json::json!({
                "domain_kind":"tuple",
                "relation_kind":"references",
                "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
                "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-"
            }),
            relation_id: "ak:relation:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz".to_owned(),
            state: "active".to_owned(),
            current_commit_id: "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4"
                .to_owned(),
            current_stream_position: 4,
            value: serde_json::json!({
                "schema":"ak.schema.relation.v1",
                "id":"ak:relation:AcFfzgdHkT6eFkto1gjLaKniVuMXx9sD0GKQwk8BXykz",
                "realm_id":"ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru",
                "effective_scope":{"kind":"realm","realm_id":"ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru"},
                "relation_kind":"references",
                "from_ref":"ak:strand:AUifoAUG8AEOHYXp999WnI7WlLt19ByDoqYUsFwbw4A4",
                "to_ref":"ak:strand:AQdknt9AByYY2gb16KB093xeB4J8b02mTEd4Mt8z2rO-",
                "state":"tombstoned",
                "created_by":{
                    "kind":"account",
                    "account_id":{
                        "principal_id":"ak:did_core:web:relation-author.example",
                        "station_id":"ak:did_core:web:relation-station.example"
                    }
                },
                "created_at":"2026-09-21T00:00:00.000Z"
            }),
        };
        assert!(matches!(
            decode_row(row),
            Err(PersistenceError::Database(_))
        ));
    }
}
