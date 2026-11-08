//! Ordinary local endpoints share the same authority cut as recovery/pairing.

use arkret_models_crypto::KeyPackagesClaimResponseBody;
use arkret_wire::DidCoreId;
use coland_storage::{PeerKeyPackageClaimAttempt, PersistenceError, PersistenceResult};
use diesel::sql_types::Text;
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension as _, RunQueryDsl as _};

use crate::AsyncPgConnection;

/// Called before touching the KeyPackage row and again before finalization.
/// Recovery and endpoint supersession own the same PCR authority locks, so
/// neither can pass between the final current check and the allocation CAS.
pub(super) async fn require_current(
    conn: &mut AsyncPgConnection,
    attempt: &PeerKeyPackageClaimAttempt<'_>,
) -> PersistenceResult<()> {
    let admission = attempt
        .admission
        .as_ref()
        .ok_or_else(|| super::denied("new claim has no original command"))?;
    let request = &admission.request;
    #[derive(QueryableByName)]
    struct Station {
        #[diesel(sql_type = Text)]
        station_id: DidCoreId,
    }
    let station = sql_query("SELECT station_id FROM device_inventory_station WHERE singleton")
        .get_result::<Station>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| super::denied("claim has no native local Station"))?
        .station_id;
    if request.service_binding.destination_id != station {
        return Err(super::denied(
            "claim destination is not this native Station",
        ));
    }
    if request.target_actor_id.is_some()
        || (request.requester_actor_id.is_some() && request.service_binding.source_id == station)
    {
        return Err(super::denied(
            "local Realm endpoint claim requires its native managed scope guard",
        ));
    }
    let outcome: KeyPackagesClaimResponseBody = serde_json::from_value(
        attempt
            .ledger
            .outcome
            .clone()
            .ok_or_else(|| super::denied("claim outcome is absent"))?,
    )
    .map_err(super::denied)?;
    let counterparts = crate::boxed_future(|| {
        crate::mls_keypackage_claim_endpoints::prepare(conn, &outcome, Some(request), &station, &[])
    })
    .await?;
    if counterparts.is_empty() {
        return Err(super::denied("claim has no native local endpoint"));
    }
    let mut realms = counterparts
        .iter()
        .map(|endpoint| endpoint.realm().clone())
        .collect::<Vec<_>>();
    realms.sort();
    realms.dedup();
    for realm in realms {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &realm).await?;
        crate::realm_management_archive::require_unfrozen(conn, &realm).await?;
        let authority = crate::authority_commit::locked_authority(conn, &realm)
            .await
            .map_err(crate::PgTransactionError::into_persistence)?
            .ok_or_else(|| super::denied("claim endpoint PCR authority is absent"))?;
        if authority.service_id != station {
            return Err(super::denied("claim endpoint PCR is not governed here"));
        }
    }
    for endpoint in &counterparts {
        crate::boxed_future(|| endpoint.require_current(conn)).await?;
    }
    if request.service_binding.source_id == station {
        crate::mls_keypackage_claim_endpoints::require_local_requester_signature(conn, request)
            .await?;
    }
    if chrono::Utc::now() >= request.expires_at {
        return Err(super::denied("claim command expired before allocation"));
    }
    Ok(())
}
