//! Realm recipients follow the authority of the accepted Add, never a fixed home Station.
use arkret_wire::{ActorId, DidCoreId, EventId, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Binary, Jsonb};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension, RunQueryDsl};

#[derive(QueryableByName)]
struct CommitRow {
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
}

pub(crate) fn matches_accepted_add(
    actor: &ActorId,
    station: &DidCoreId,
    commit: &RealmCommit,
) -> bool {
    if let Some(home) = actor.fixed_route_service_id() {
        return home == station;
    }
    let Some(subject) = actor.as_realm_actor_id() else {
        return false;
    };
    subject.realm_id == commit.realm_id
        && arkret_identity::verification_method_did(commit.signature.verification_method.as_str())
            .ok()
            .and_then(|did| arkret_wire::project_did_to_core_id(&did).ok())
            .is_some_and(|service| &service == station)
}

pub(crate) async fn accepted_add_matches(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    station: &DidCoreId,
    event: &EventId,
) -> PersistenceResult<bool> {
    let Some(row) = sql_query("SELECT c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE e.id=$1 AND e.state='committed' AND e.kind='ak.mls.commit'")
        .bind::<Binary, _>(event.token_bytes().to_vec()).get_result::<CommitRow>(&mut *conn).await.optional()
        .map_err(PersistenceError::database)? else { return Ok(false); };
    let commit: RealmCommit =
        serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
    Ok(commit.event_ref == *event && matches_accepted_add(actor, station, &commit))
}
