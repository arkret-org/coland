//! Immutable verified Agent producer closure retained at the accepting cut.
use arkret_identity::agent_authority_evidence::VerifiedAgentProducer;
use arkret_wire::{Event, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_query;
use diesel::sql_types::{Jsonb, Text};
use diesel_async::AsyncPgConnection;
use horme::RunQueryDsl;

pub(crate) async fn retain_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    producer: &VerifiedAgentProducer,
) -> PersistenceResult<()> {
    if event.actual_signer().as_account_id() != Some(producer.account())
        || commit.event_ref != event.event_id
    {
        return Err(PersistenceError::SchemaViolation(
            "Agent producer evidence differs from accepted Event".into(),
        ));
    }
    let body = serde_json::to_value(producer.evidence()).map_err(PersistenceError::database)?;
    sql_query("INSERT INTO forwarded_producer_agent_evidence (commit_id,evidence_ref,principal_id,station_id,evidence_json) VALUES($1,$2,$3,$4,$5)")
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(producer.reference().as_ref())
        .bind::<Text,_>(producer.account().principal_id.as_str()).bind::<Text,_>(producer.account().station_id.as_str())
        .bind::<Jsonb,_>(body).execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}
