//! Home-Station ordinary requester intents, independent of destination custody.

use arkret_models_crypto::{KeyPackagesClaimRequestBody, PeerKeyPackageRequesterAuthorization};
use arkret_wire::DidCoreId;
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Binary, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncConnection as _;
use horme::{OptionalExtension as _, RunQueryDsl as _};

use crate::{PgPool, PgTransactionError, pg_conn};

fn denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: ordinary claim origin {detail}"))
}

fn require_window(
    request: &KeyPackagesClaimRequestBody,
    transport_expires_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let signed_at = match &request.requester_authorization {
        PeerKeyPackageRequesterAuthorization::Device { signed_at, .. }
        | PeerKeyPackageRequesterAuthorization::Agent { signed_at, .. } => *signed_at,
        _ => return Err(denied("does not accept a Realm requester")),
    };
    let now = chrono::Utc::now();
    if now >= transport_expires_at
        || now >= request.expires_at
        || signed_at > now + chrono::Duration::seconds(60)
        || request.expires_at <= signed_at
        || request.expires_at - signed_at > chrono::Duration::seconds(300)
    {
        return Err(denied("request or transport window ended"));
    }
    Ok(())
}

#[derive(QueryableByName)]
struct Source {
    #[diesel(sql_type = Jsonb)]
    actor_id: serde_json::Value,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Jsonb)]
    request_body: serde_json::Value,
    #[diesel(sql_type = Text)]
    authorization_event_ref: String,
    #[diesel(sql_type = Text)]
    authorization_commit_id: String,
}

/// This is pre-dispatch retention, not a reservation, membership proof or a
/// permission to install a remote leaf. Even a crash before outbox enqueue
/// leaves an obligation for the recovery coordinator to reconcile.
pub(crate) async fn prepare(
    pool: &PgPool,
    request: &KeyPackagesClaimRequestBody,
    transport_expires_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<bool> {
    request.validate_shape().map_err(denied)?;
    require_window(request, transport_expires_at)?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async |conn| {
        let local = sql_query("SELECT to_jsonb(station_id) AS payload FROM device_inventory_station WHERE singleton")
            .get_result::<crate::JsonPayloadRow>(&mut *conn).await.optional()
            .map_err(PersistenceError::database)?.ok_or_else(|| denied("has no native Station"))?;
        let station: DidCoreId = serde_json::from_value(local.payload).map_err(denied)?;
        let (endpoint, actor, authorization) = crate::mls_keypackage_claim_endpoints::ordinary_requester(
            conn, request, &station
        ).await?;
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, endpoint.realm()).await?;
        crate::realm_management_archive::require_unfrozen(conn, endpoint.realm()).await?;
        let authority = crate::authority_commit::locked_authority(conn, endpoint.realm()).await?
            .ok_or_else(|| denied("PCR authority is absent"))?;
        if authority.service_id != station {
            return Err(denied("PCR is not governed by this home Station").into());
        }
        crate::boxed_future(|| endpoint.require_current(conn)).await?;
        crate::mls_keypackage_claim_endpoints::require_local_requester_signature(conn, request).await?;
        require_window(request, transport_expires_at)?;
        let digest = arkret_canonical::canonical_sha256(request).map_err(denied)?;
        let body = serde_json::to_value(request).map_err(denied)?;
        let actor = serde_json::to_value(actor).map_err(denied)?;
        let inserted = sql_query("INSERT INTO ordinary_keypackage_claim_sources(source_id,claim_request_id,actor_id,request_digest,request_body,authorization_event_pk,authorization_commit_id) SELECT $1,$2,$3,$4,$5,e.pk,$7 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$6 AND e.state='committed' AND c.commit_id=$7 ON CONFLICT(source_id,claim_request_id) DO NOTHING")
            .bind::<Text, _>(station.as_str()).bind::<Text, _>(request.claim_request_id.as_str())
            .bind::<Jsonb, _>(&actor).bind::<Text, _>(&digest).bind::<Jsonb, _>(&body)
            .bind::<Binary, _>(authorization.event_id.token_bytes().to_vec())
            .bind::<Text, _>(authorization.commit_id.as_str())
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        let original = sql_query("SELECT s.actor_id,s.request_digest,s.request_body,e.envelope->>'event_id' AS authorization_event_ref,s.authorization_commit_id FROM ordinary_keypackage_claim_sources s JOIN canonical_events e ON e.pk=s.authorization_event_pk WHERE s.source_id=$1 AND s.claim_request_id=$2 FOR SHARE OF s,e")
            .bind::<Text, _>(station.as_str()).bind::<Text, _>(request.claim_request_id.as_str())
            .get_result::<Source>(&mut *conn).await.optional().map_err(PersistenceError::database)?
            .ok_or_else(|| denied("original authorization disappeared"))?;
        if original.actor_id != actor || original.request_digest != digest || original.request_body != body
            || original.authorization_event_ref != authorization.event_id.as_str()
            || original.authorization_commit_id != authorization.commit_id.as_str()
        {
            return Err(PersistenceError::Conflict("duplicate_conflict: ordinary claim source identity already has another intent".into()).into());
        }
        // All writer waits happened under the same PCR fence as recovery.
        crate::boxed_future(|| endpoint.require_current(conn)).await?;
        require_window(request, transport_expires_at)?;
        Ok(inserted == 1)
    }).await.map_err(PgTransactionError::into_persistence)
}
