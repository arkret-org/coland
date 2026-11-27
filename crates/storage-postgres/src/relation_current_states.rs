use arkret_models_collaboration::objects::relation::{Relation, RelationPrimaryConflictDomain};
use arkret_wire::{CurrentRevision, RealmCommitId, RelationState};

use super::{
    AsyncPgConnection, BigInt, Jsonb, OptionalExtension, PersistenceError, PersistenceResult,
    PgPool, QueryableByName, RelationCurrentStateRecord, RelationCurrentStateStore, RunQueryDsl,
    Text, async_trait, sql_query,
};

pub struct PgRelationCurrentStateStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct RelationCurrentStateReadRow {
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

fn decode_row(row: RelationCurrentStateReadRow) -> PersistenceResult<RelationCurrentStateRecord> {
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
    Ok(RelationCurrentStateRecord {
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
    current: RelationCurrentStateReadRow,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    source_stream_ref: Option<serde_json::Value>,
}

pub(crate) async fn snapshot_rows_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Vec<arkret_wire::CurrentState>> {
    let rows = sql_query(
        "SELECT result.*, covering.stream_ref AS source_stream_ref \
         FROM relation_current_states result LEFT JOIN realm_commits covering \
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
            let expected = arkret_wire::CommitStreamRef::Realm { realm_id: realm_id.clone() };
            if source_stream_ref != expected {
                return Err(corrupt(
                    "Relation current source differs from its value scope",
                ));
            }
            Ok(arkret_wire::CurrentState::Value {
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
}

fn precondition(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "{}: {detail}",
        coland_storage::ConflictCode::FailedPrecondition
    ))
}

/// Authorize an ordinary Relation against its signed Realm and covering Commit.
pub(crate) async fn authorize_relation_write_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.scope_ref != arkret_wire::ScopeRef::realm(event.realm_id.clone())
        || commit.event_ref != event.event_id
        || commit.stream_ref != (arkret_wire::CommitStreamRef::Realm { realm_id: event.realm_id.clone() })
    {
        return Err(precondition(
            "Relation write differs from its accepting source stream",
        ));
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
        conn, event, commit, prepared,
    )
    .await.map(|_| ())
}

async fn endpoint_home(
    conn: &mut AsyncPgConnection,
    endpoint: &str,
) -> PersistenceResult<Option<EndpointHomeRow>> {
    let query = if endpoint.starts_with("ak:strand:") {
        "SELECT realm_id \
         FROM strand_current_states WHERE strand_id=$1 ORDER BY realm_id LIMIT 1"
    } else if endpoint.starts_with("ak:space:") {
        "SELECT realm_id \
         FROM space_current_states WHERE space_id=$1 ORDER BY realm_id LIMIT 1"
    } else if endpoint.starts_with("ak:message:") {
        "SELECT realm_id \
         FROM message_revision_current_states WHERE message_id=$1 ORDER BY realm_id LIMIT 1"
    } else {
        return Ok(None);
    };
    sql_query(query)
        .bind::<Text, _>(endpoint)
        .get_result::<EndpointHomeRow>(conn)
        .await
        .optional()
        .map_err(PersistenceError::database)
}

/// Structural endpoints must belong to the accepting Realm. A Space that
/// contains another object applies its current placement policy at this cut.
pub(crate) async fn require_relation_value_scope_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    before: Option<&Relation>,
    after: &Relation,
    created: bool,
) -> PersistenceResult<()> {
    for value in before.into_iter().chain(std::iter::once(after)) {
        if value.realm_id != event.realm_id || value.effective_scope.as_ref().is_some_and(|scope| scope != &event.scope_ref) {
            return Err(precondition(arkret_wire::ReasonCode::SCOPE_REF_MISMATCH));
        }
    }
    let relation_kind = after.relation_kind.as_str();
    if !created || !arkret_models_collaboration::objects::relation::relation_kind_is_structural(relation_kind) {
        return Ok(());
    }
    for endpoint in [&after.from_ref, &after.to_ref] {
        let Some(endpoint) = endpoint.as_object_ref() else {
            return Err(precondition("structural Relation requires object endpoints"));
        };
        let home = endpoint_home(conn, endpoint).await?;
        if home
                .as_ref()
                .is_none_or(|home| home.realm_id != event.realm_id.as_str())
        {
            return Err(PersistenceError::Conflict(format!(
                "{}: structural Relation endpoint {endpoint} is not an object of this Realm",
                coland_storage::ConflictCode::CrossRealmStructuralRelation
            )));
        }
    }
    let container = match relation_kind {
        "contains" => after.from_ref.as_object_ref(),
        "belongs_to" => after.to_ref.as_object_ref(),
        _ => None,
    };
    if let Some(parent_id) = container.filter(|reference| reference.starts_with("ak:space:")) {
        let position = i64::try_from(commit.stream_position).map_err(PersistenceError::database)?;
        crate::space_current_states::require_parent_in_connection(conn, event, position, parent_id).await?;
    }
    Ok(())
}

#[async_trait]
impl RelationCurrentStateStore for PgRelationCurrentStateStore {
    async fn snapshot_all(&self) -> PersistenceResult<Vec<RelationCurrentStateRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        let rows = sql_query(
            "SELECT realm_id,domain_key,domain,relation_id,state,current_commit_id,\
             current_stream_position,value FROM relation_current_states \
             ORDER BY realm_id ASC,domain_key ASC",
        )
        .load::<RelationCurrentStateReadRow>(&mut conn)
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
        let row = RelationCurrentStateReadRow {
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
