//! Durable local endpoint discovery rooted in accepted Genesis/Add originals.
//! These rows locate evidence; they never prove a complete recovery census.

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::mls_roster_authority::MlsAddAuthorityAttestation;
use arkret_models_crypto::ContentEndpoint;
use arkret_wire::{CommittedEventRef, Event, EventId, RealmCommit, ScopeRef};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Binary, Jsonb, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension as _, RunQueryDsl as _};

use crate::AsyncPgConnection;

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: endpoint history {detail}"))
}

#[derive(QueryableByName)]
struct Source {
    #[diesel(sql_type = BigInt)]
    event_pk: i64,
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
}

#[derive(QueryableByName)]
struct Stored {
    #[diesel(sql_type = Jsonb)]
    effective_scope: serde_json::Value,
    #[diesel(sql_type = Text)]
    genesis_event_ref: String,
    #[diesel(sql_type = Jsonb)]
    binding: serde_json::Value,
}

/// Only native admission/replication writers call this, after their original
/// producer, claim and RFC checks. The original accepted Event is retained by
/// FK; the home index is not part of a governor's transferable private state.
pub(crate) async fn record(
    conn: &mut AsyncPgConnection,
    scope: &ScopeRef,
    genesis: &EventId,
    endpoint: &ContentEndpoint,
    source_event: &EventId,
) -> PersistenceResult<()> {
    let Some(account) = endpoint.actor_id.as_account_id() else {
        return Ok(());
    };
    let station = sql_query(
        "SELECT to_jsonb(station_id) AS payload FROM device_inventory_station WHERE singleton",
    )
    .get_result::<crate::JsonPayloadRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| invalid("has no native local Station"))?;
    if station.payload.as_str() != Some(account.station_id.as_str()) {
        return Ok(());
    }
    endpoint.validate().map_err(invalid)?;
    let token = crate::ids::parse_event_id(source_event.as_str())
        .ok_or_else(|| invalid("source Event ID is invalid"))?;
    let source = sql_query("SELECT e.pk AS event_pk,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.state='committed'")
        .bind::<Binary, _>(token.to_vec()).get_result::<Source>(&mut *conn).await.optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| invalid("has no exact accepted source original"))?;
    let commit: RealmCommit = serde_json::from_value(source.commit_json).map_err(invalid)?;
    if commit.event_ref != *source_event
        || commit.stream_ref
            != arkret_wire::CommitStreamRef::from_scope(scope, None).map_err(invalid)?
    {
        return Err(invalid("source original differs from the exact scope"));
    }
    let first_source = CommittedEventRef {
        event_id: source_event.clone(),
        commit_id: commit.commit_id,
        stream_ref: commit.stream_ref,
        stream_position: commit.stream_position,
    };
    let key = arkret_canonical::canonical_sha256(&(scope, genesis, endpoint))
        .map_err(PersistenceError::database)?;
    let scope = serde_json::to_value(scope).map_err(PersistenceError::database)?;
    let binding = serde_json::to_value(endpoint).map_err(PersistenceError::database)?;
    sql_query("INSERT INTO content_endpoint_admission_history(admission_key,effective_scope,genesis_event_ref,binding,first_source,source_event_pk,admitted_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(admission_key) DO NOTHING")
        .bind::<Text, _>(&key).bind::<Jsonb, _>(&scope).bind::<Text, _>(genesis.as_str())
        .bind::<Jsonb, _>(&binding).bind::<Jsonb, _>(serde_json::to_value(first_source).map_err(PersistenceError::database)?)
        .bind::<BigInt, _>(source.event_pk).bind::<Timestamptz, _>(commit.committed_at)
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    let stored = sql_query("SELECT effective_scope,genesis_event_ref,binding FROM content_endpoint_admission_history WHERE admission_key=$1")
        .bind::<Text, _>(&key).get_result::<Stored>(&mut *conn).await.map_err(PersistenceError::database)?;
    if stored.effective_scope != scope
        || stored.genesis_event_ref != genesis.as_str()
        || stored.binding != binding
    {
        return Err(invalid("native index digest collision"));
    }
    Ok(())
}

pub(crate) async fn record_genesis(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::MlsGenesis {
        return Ok(());
    }
    let creator = event
        .as_mls_genesis()
        .map_err(invalid)?
        .creator_leaf_authority;
    let endpoint = ContentEndpoint {
        actor_id: event
            .executed_by
            .as_ref()
            .unwrap_or(&event.actor_id)
            .clone(),
        endpoint: creator.endpoint,
        authorization_event_ref: creator.authorization_event_ref,
        signature_key_base64url: creator.leaf_signature_key_base64url.to_string(),
    };
    record(
        conn,
        &event.scope_ref,
        &event.event_id,
        &endpoint,
        &event.event_id,
    )
    .await
}

pub(crate) async fn record_add(
    conn: &mut AsyncPgConnection,
    attestation: &MlsAddAuthorityAttestation,
) -> PersistenceResult<()> {
    let endpoint = ContentEndpoint {
        actor_id: attestation.actor_id.clone(),
        endpoint: attestation.endpoint.clone(),
        authorization_event_ref: attestation.authorization_event_ref.clone(),
        signature_key_base64url: attestation.leaf_signature_key_base64url.to_string(),
    };
    record(
        conn,
        &attestation.effective_scope,
        &attestation.genesis_event_ref,
        &endpoint,
        &attestation.commit_event_ref,
    )
    .await
}
