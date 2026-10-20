//! Immutable original Station method history for Realm target claims.
use arkret_models_identity::AuthenticatedServiceResolution;
use coland_storage::{PeerKeyPackageClaimAttempt, PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "capability_denied: original Realm claim history: {detail}"
    ))
}
#[derive(QueryableByName)]
struct History {
    #[diesel(sql_type = Jsonb)]
    resolution: Value,
    #[diesel(sql_type = Jsonb)]
    outcome: Value,
}
#[derive(QueryableByName)]
struct RealmRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
}

pub(crate) async fn original(
    conn: &mut AsyncPgConnection,
    claim_request_id: &str,
    request_digest: &str,
) -> PersistenceResult<Option<arkret_models_crypto::PeerKeyPackagesClaimRequestBody>> {
    let rows = sql_query("SELECT request_body AS payload FROM keypackage_claim_sources WHERE claim_request_id=$1 AND request_digest=$2 LIMIT 2")
        .bind::<Text,_>(claim_request_id).bind::<Text,_>(request_digest)
        .get_results::<crate::JsonPayloadRow>(conn).await.map_err(PersistenceError::database)?;
    if rows.len() > 1 {
        return Err(invalid("ambiguous original request"));
    }
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let request: arkret_models_crypto::PeerKeyPackagesClaimRequestBody =
        serde_json::from_value(row.payload).map_err(invalid)?;
    request.validate_shape().map_err(invalid)?;
    if request.claim_request_id.as_str() != claim_request_id
        || arkret_canonical::canonical_sha256(&request).map_err(invalid)? != request_digest
    {
        return Err(invalid("original request digest mismatch"));
    }
    Ok(Some(request))
}

pub(crate) async fn lock_mutation(
    conn: &mut AsyncPgConnection,
    source_id: &str,
    claim_request_id: &str,
) -> PersistenceResult<()> {
    let row=sql_query("SELECT governing_realm_id AS realm_id FROM keypackage_claim_sources WHERE source_id=$1 AND claim_request_id=$2 AND governing_realm_id IS NOT NULL")
        .bind::<Text,_>(source_id).bind::<Text,_>(claim_request_id)
        .get_result::<RealmRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(row) = row {
        let realm = arkret_wire::RealmId::new(row.realm_id).map_err(invalid)?;
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &realm).await?;
        crate::realm_management_archive::require_unfrozen(conn, &realm).await?;
    }
    Ok(())
}

pub(crate) async fn retain(
    conn: &mut AsyncPgConnection,
    attempt: &PeerKeyPackageClaimAttempt<'_>,
) -> PersistenceResult<()> {
    let Some(admission) = &attempt.admission else {
        return Ok(());
    };
    if admission.request.target_actor_id.is_none() {
        if admission.claim_issuer_resolution.is_some() {
            return Err(invalid(
                "ordinary targets cannot carry Realm private history",
            ));
        }
        return Ok(());
    }
    let resolution = admission
        .claim_issuer_resolution
        .as_ref()
        .ok_or_else(|| invalid("issuing Station history is absent"))?;
    let outcome: arkret_models_crypto::PeerKeyPackagesClaimOutcome = serde_json::from_value(
        attempt
            .ledger
            .outcome
            .clone()
            .ok_or_else(|| invalid("claim outcome absent"))?,
    )
    .map_err(invalid)?;
    let receipt = &outcome.claim_receipt;
    let authority = receipt
        .claim_authority_ref
        .as_ref()
        .ok_or_else(|| invalid("original governance reference absent"))?;
    if resolution.service_kind != "station" {
        return Err(invalid("claim issuer is not a Station"));
    }
    arkret::verify_peer_keypackage_claim_receipt_signature(receipt, resolution).map_err(invalid)?;
    crate::realm_management_history::require_issuer(
        conn,
        &admission.request.intended_realm_id,
        &receipt.destination_id,
        Some(authority),
        receipt.claimed_at,
    )
    .await?;
    sql_query("INSERT INTO realm_claim_issuer_histories(realm_id,source_id,claim_request_id,resolution) VALUES($1,$2,$3,$4)")
        .bind::<Text,_>(admission.request.intended_realm_id.as_str())
        .bind::<Text,_>(&attempt.ledger.source_id)
        .bind::<Text,_>(&attempt.ledger.claim_request_id)
        .bind::<Jsonb,_>(serde_json::to_value(resolution).map_err(invalid)?)
        .execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) async fn read(
    conn: &mut AsyncPgConnection,
    source_id: &str,
    claim_request_id: &str,
) -> PersistenceResult<Option<AuthenticatedServiceResolution>> {
    let row = sql_query("SELECT h.resolution,c.outcome FROM realm_claim_issuer_histories h JOIN peer_keypackage_claims c ON c.source_id=h.source_id AND c.claim_request_id=h.claim_request_id WHERE h.source_id=$1 AND h.claim_request_id=$2")
        .bind::<Text,_>(source_id).bind::<Text,_>(claim_request_id)
        .get_result::<History>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(row) = row else { return Ok(None) };
    let outcome: arkret_models_crypto::PeerKeyPackagesClaimOutcome =
        serde_json::from_value(row.outcome).map_err(invalid)?;
    let resolution: AuthenticatedServiceResolution =
        serde_json::from_value(row.resolution).map_err(invalid)?;
    let receipt = &outcome.claim_receipt;
    if receipt.source_id.as_str() != source_id
        || receipt.claim_request_id.as_str() != claim_request_id
        || receipt.request.target_actor_id.is_none()
        || resolution.service_kind != "station"
    {
        return Err(invalid("frozen history belongs to another claim"));
    }
    arkret::verify_peer_keypackage_claim_receipt_signature(receipt, &resolution)
        .map_err(invalid)?;
    crate::realm_management_history::require_issuer(
        conn,
        &receipt.request.intended_realm_id,
        &receipt.destination_id,
        Some(
            receipt
                .claim_authority_ref
                .as_ref()
                .ok_or_else(|| invalid("original governance reference absent"))?,
        ),
        receipt.claimed_at,
    )
    .await?;
    Ok(Some(resolution))
}
