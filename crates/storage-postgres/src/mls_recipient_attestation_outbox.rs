//! Frozen recipient proofs are retained until exact governance installation.

use arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody;
use arkret_wire::{EventId, Hash, MlsWelcomeDeliveryId};
use chrono::{DateTime, Utc};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};

use crate::{
    OptionalExtension, PersistenceError, PersistenceResult, PgPool, QueryableByName, RunQueryDsl,
    sql_query,
};

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type = Text)]
    attestation_digest: String,
    #[diesel(sql_type = Jsonb)]
    request_json: serde_json::Value,
}

fn decode(row: Row) -> PersistenceResult<MlsAttestAddRequestBody> {
    let request: MlsAttestAddRequestBody =
        serde_json::from_value(row.request_json).map_err(PersistenceError::database)?;
    request
        .validate_claim_binding()
        .map_err(PersistenceError::database)?;
    if arkret_canonical::canonical_sha256(&request).map_err(PersistenceError::database)?
        != row.attestation_digest
    {
        return Err(PersistenceError::Internal(
            "recipient proof digest mismatch".into(),
        ));
    }
    Ok(request)
}

pub(crate) async fn get(
    pool: &PgPool,
    commit: &EventId,
    welcome: &MlsWelcomeDeliveryId,
) -> PersistenceResult<Option<MlsAttestAddRequestBody>> {
    let mut conn = crate::pg_db(pool);
    sql_query("SELECT attestation_digest,request_json FROM mls_add_authority_attestation_outbox WHERE commit_event_ref=$1 AND welcome_id=$2")
        .bind::<Text, _>(commit.as_str()).bind::<Text, _>(welcome.as_str())
        .get_result::<Row>(&mut conn).await.optional().map_err(PersistenceError::database)?
        .map(decode).transpose()
}

pub(crate) async fn pending(
    pool: &PgPool,
    limit: usize,
) -> PersistenceResult<Vec<MlsAttestAddRequestBody>> {
    let limit = i64::try_from(limit).map_err(PersistenceError::database)?;
    let mut conn = crate::pg_db(pool);
    sql_query("SELECT attestation_digest,request_json FROM mls_add_authority_attestation_outbox WHERE acknowledged_at IS NULL ORDER BY created_at,commit_event_ref,welcome_id LIMIT $1")
        .bind::<BigInt, _>(limit).load::<Row>(&mut conn).await
        .map_err(PersistenceError::database)?.into_iter().map(decode).collect()
}

pub(crate) async fn acknowledge(
    pool: &PgPool,
    request: &MlsAttestAddRequestBody,
    digest: &Hash,
    at: DateTime<Utc>,
) -> PersistenceResult<()> {
    if arkret_canonical::canonical_sha256(request).map_err(PersistenceError::database)?
        != digest.as_str()
    {
        return Err(PersistenceError::SchemaViolation(
            "governance acknowledged another recipient proof".into(),
        ));
    }
    let mut conn = crate::pg_db(pool);
    let changed = sql_query("UPDATE mls_add_authority_attestation_outbox SET acknowledged_at=COALESCE(acknowledged_at,$4) WHERE commit_event_ref=$1 AND welcome_id=$2 AND attestation_digest=$3")
        .bind::<Text, _>(request.attestation.commit_event_ref.as_str())
        .bind::<Text, _>(request.attestation.welcome_id.as_str())
        .bind::<Text, _>(digest.as_str()).bind::<Timestamptz, _>(at)
        .execute(&mut conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: recipient proof acknowledgement differs from frozen outbox".into(),
        ));
    }
    Ok(())
}
