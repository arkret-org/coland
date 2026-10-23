//! Original private artifacts retain their issuing tenure through installed handoffs.
use arkret_wire::{DidCoreId, RealmCommitAuthorityRef, RealmId};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use horme::RunQueryDsl;
use serde_json::Value;

#[derive(QueryableByName)]
struct Authority {
    #[diesel(sql_type = BigInt)]
    generation: i64,
    #[diesel(sql_type = Text)]
    service_id: String,
    #[diesel(sql_type = Jsonb)]
    authority_ref: Value,
}
#[derive(QueryableByName)]
struct Handoff {
    #[diesel(sql_type = Jsonb)]
    handoff_json: Value,
}
#[derive(QueryableByName)]
struct Outgoing {
    #[diesel(sql_type = Timestamptz)]
    committed_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = BigInt)]
    generation: i64,
    #[diesel(sql_type = Jsonb)]
    authority_ref: Value,
}

/// Only installed, already verified handoffs may connect a historical issuer.
/// An original reference must name its exact tenure, not another tenure held
/// by the same Station. A cursor has no reference and retains its original
/// private issuance row instead.
pub(crate) async fn require_issuer(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    issuer: &DidCoreId,
    original_ref: Option<&RealmCommitAuthorityRef>,
    issued_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let invalid = || {
        PersistenceError::Conflict(
            "capability_denied: original issuer has no complete installed governance chain".into(),
        )
    };
    let current = sql_query(
        "SELECT generation,service_id,authority_ref FROM realm_authorities WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<Authority>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let governance =
        crate::pcr_private_authority::validate_installed_governance(conn, realm).await?;
    governance
        .validate_current(issuer, 0)
        .map_err(crate::pcr_private_authority::refused)?;
    let expected_ref = original_ref
        .map(serde_json::to_value)
        .transpose()
        .map_err(PersistenceError::database)?;
    let mut matched = false;
    let mut upper = None;
    let rows = sql_query(
        "SELECT handoff_json FROM realm_authority_handoffs WHERE realm_id=$1 ORDER BY to_generation DESC",
    )
    .bind::<Text, _>(realm.as_str())
    .get_results::<Handoff>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut generation = u64::try_from(current.generation).map_err(|_| invalid())?;
    let mut service = current.service_id;
    let mut authority_ref = current.authority_ref;
    for row in rows {
        let handoff: arkret_wire::RealmAuthorityHandoff =
            serde_json::from_value(row.handoff_json).map_err(PersistenceError::database)?;
        if handoff.realm_id != *realm
            || handoff.to_generation != generation
            || handoff.from_generation.checked_add(1) != Some(generation)
            || handoff.to_service_id.as_str() != service
            || authority_ref
                != serde_json::to_value(RealmCommitAuthorityRef::Handoff(handoff.handoff_id))
                    .map_err(PersistenceError::database)?
        {
            return Err(invalid());
        }
        matched |= service == issuer.as_str()
            && expected_ref
                .as_ref()
                .is_none_or(|value| value == &authority_ref)
            && issued_at >= handoff.new_authority_acceptance_signature.created_at
            && upper.is_none_or(|end| issued_at <= end);
        generation = handoff.from_generation;
        service = handoff.from_service_id.to_string();
        // The terminal change is an accepted original of the outgoing tenure.
        // Its authority reference remains unchanged after installation.
        let outgoing = sql_query(
            "SELECT committed_at, governance_generation AS generation, commit_json->'authority_ref' AS authority_ref FROM realm_commits WHERE realm_id=$1 AND commit_id=$2",
        )
        .bind::<Text, _>(realm.as_str())
        .bind::<Text, _>(handoff.change_commit_id.as_str())
        .get_result::<Outgoing>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if outgoing.generation != i64::try_from(generation).map_err(|_| invalid())? {
            return Err(invalid());
        }
        authority_ref = outgoing.authority_ref;
        upper = Some(outgoing.committed_at);
    }
    let genesis=sql_query("SELECT committed_at, governance_generation AS generation, commit_json->'authority_ref' AS authority_ref FROM realm_commits WHERE realm_id=$1 AND stream_ref->>'kind'='realm' ORDER BY stream_position LIMIT 1")
        .bind::<Text,_>(realm.as_str()).get_result::<Outgoing>(&mut *conn).await.map_err(PersistenceError::database)?;
    matched |= service == issuer.as_str()
        && expected_ref
            .as_ref()
            .is_none_or(|value| value == &authority_ref)
        && issued_at >= genesis.committed_at
        && upper.is_none_or(|end| issued_at <= end);
    if generation != 0
        || genesis.generation != 0
        || genesis.authority_ref != authority_ref
        || !matched
    {
        return Err(invalid());
    }
    Ok(())
}
