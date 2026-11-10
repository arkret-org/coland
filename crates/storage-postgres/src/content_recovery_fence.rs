//! Serialize new local endpoint sources with native replacement episodes.

use arkret_wire::ActorId;
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Bool, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension as _, RunQueryDsl as _};

use crate::{AsyncPgConnection, JsonPayloadRow};

#[derive(QueryableByName)]
struct Blocked {
    #[diesel(sql_type = Bool)]
    blocked: bool,
}

/// Foreign sources are qualified at their own Station. For a local Account,
/// take the same PCR authority lock as the recovery unit before observing the
/// intent, even when no episode exists yet; absence cannot race its creation.
pub(crate) async fn require_unfenced(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
) -> PersistenceResult<()> {
    let Some(account) = actor.as_account_id() else {
        return Ok(());
    };
    let station = sql_query(
        "SELECT to_jsonb(station_id) AS payload FROM device_inventory_station WHERE singleton",
    )
    .get_result::<JsonPayloadRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| {
        PersistenceError::Conflict(
            "revision_unavailable: recovery membership fence has no native Station".into(),
        )
    })?;
    if station.payload.as_str() != Some(account.station_id.as_str()) {
        return Ok(());
    }
    // Membership installation can already hold its business Realm. Never
    // wait backwards on a busy subject PCR and form a lock cycle.
    sql_query("SELECT to_jsonb(a.realm_id) AS payload FROM principal_resolutions p JOIN realm_authorities a ON a.realm_id=p.pcr_realm_id WHERE p.principal_id=$1 AND p.station_id=$2 FOR UPDATE OF a NOWAIT")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_result::<JsonPayloadRow>(&mut *conn).await.optional()
        .map_err(|_| PersistenceError::Conflict("temporarily_unavailable: recovery membership subject cut is busy or unavailable".into()))?
        .ok_or_else(|| PersistenceError::Conflict("revision_unavailable: recovery membership subject has no native PCR".into()))?;
    crate::pcr_private_authority::lock_holder(conn, account, Some(&account.station_id)).await?;
    let blocked = sql_query("SELECT EXISTS(SELECT 1 FROM content_recovery_episodes WHERE actor_id=$1 AND security_completed_at IS NULL) AS blocked")
        .bind::<Jsonb,_>(serde_json::to_value(actor).map_err(PersistenceError::database)?)
        .get_result::<Blocked>(conn).await.map_err(PersistenceError::database)?;
    if blocked.blocked {
        return Err(PersistenceError::Conflict(
            "failed_precondition: native content recovery membership fence is active".into(),
        ));
    }
    Ok(())
}
