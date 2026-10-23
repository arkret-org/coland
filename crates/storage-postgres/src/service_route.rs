use arkret_models_identity::{
    AuthenticatedServiceResolution, ServiceMethodState, VerifiedServiceRoute,
};
use arkret_wire::{DidCoreId, Hash};
use coland_storage::{
    MonotonicRouteWrite, PersistenceError, PersistenceResult, ServiceResolutionForkEvidence,
    ServiceRouteStore, ServiceRouteStoredKey,
};
use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncConnection;
use horme::{OptionalExtension, RunQueryDsl};

use crate::{PgPool, PgTransactionError, async_trait, pg_conn};

pub struct PgServiceRouteStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
struct CachedRouteRow {
    #[diesel(sql_type = Jsonb)]
    entry: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    method_state: serde_json::Value,
}

/// Choose only the initial transport state of an atomic Realm fanout intent.
/// The dispatcher still resolves the current route and revalidates the frozen
/// membership basis before sending. Cache loss never removes an obligation.
pub(crate) async fn cached_station_base_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    service_id: &DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<String>> {
    let row = sql_query(
        "SELECT r.entry, m.method_state FROM service_route_cache r \
         JOIN service_method_states m USING (service_id, service_kind) \
         WHERE r.service_id=$1 AND r.service_kind='station' \
           AND r.cache_expires_at > $2 AND NOT EXISTS (\
             SELECT 1 FROM service_resolution_fork_quarantine q \
             WHERE q.service_id=r.service_id AND q.service_kind=r.service_kind)",
    )
    .bind::<Text, _>(service_id.as_str())
    .bind::<Timestamptz, _>(at)
    .get_result::<CachedRouteRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    // An undecodable replaceable cache is a miss, as in route_cache below.
    let (Ok(route), Ok(floor)) = (
        decode::<VerifiedServiceRoute>(row.entry),
        decode::<ServiceMethodState>(row.method_state),
    ) else {
        return Ok(None);
    };
    Ok((route.service_id() == service_id
        && route.service_kind() == "station"
        && route.is_routable_at(at)
        && floor.service_id == *service_id
        && floor.service_kind == "station"
        && route.did() == &floor.did
        && route.method_history_head() == floor.method_history_head
        && route.version_id() == floor.version_id)
        .then(|| route.base_url().to_owned()))
}

#[derive(QueryableByName)]
struct ExistsRow {
    #[diesel(sql_type = Bool)]
    found: bool,
}

#[derive(QueryableByName)]
struct RouteKeyRow {
    #[diesel(sql_type = Text)]
    service_id: DidCoreId,
    #[diesel(sql_type = Text)]
    service_kind: String,
}

#[derive(QueryableByName)]
struct QuarantineRow {
    #[diesel(sql_type = Text)]
    service_id: DidCoreId,
    #[diesel(sql_type = Text)]
    service_kind: String,
    #[diesel(sql_type = Text)]
    version_id: String,
    #[diesel(sql_type = Text)]
    accepted_digest: String,
    #[diesel(sql_type = Text)]
    conflicting_digest: String,
    #[diesel(sql_type = Jsonb)]
    evidence: serde_json::Value,
    #[diesel(sql_type = Timestamptz)]
    quarantined_at: chrono::DateTime<chrono::Utc>,
}

fn encode<T: serde::Serialize>(value: &T) -> PersistenceResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|error| PersistenceError::Internal(error.to_string()))
}

fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(|error| PersistenceError::Internal(error.to_string()))
}

#[async_trait]
impl ServiceRouteStore for PgServiceRouteStore {
    async fn list_stored_route_keys(
        &self,
        after: Option<&ServiceRouteStoredKey>,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceRouteStoredKey>> {
        let (after_service_id, after_service_kind) = after
            .map(|key| (key.service_id.as_str(), key.service_kind.as_str()))
            .unwrap_or(("", ""));
        let mut conn = crate::pg_db(&self.pool);
        let rows = sql_query(
            "SELECT service_id, service_kind FROM (\
             SELECT service_id, service_kind FROM service_method_states UNION \
             SELECT service_id, service_kind FROM service_resolution_fork_quarantine UNION \
             SELECT service_id, service_kind FROM service_route_cache) AS route_keys \
             WHERE service_id > $1 OR (service_id = $1 AND service_kind > $2) \
             ORDER BY service_id ASC, service_kind ASC LIMIT $3",
        )
        .bind::<Text, _>(after_service_id)
        .bind::<Text, _>(after_service_kind)
        .bind::<BigInt, _>(i64::try_from(limit.clamp(1, 256)).unwrap_or(256))
        .load::<RouteKeyRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                Ok(ServiceRouteStoredKey {
                    service_id: row.service_id,
                    service_kind: row.service_kind,
                })
            })
            .collect()
    }

    async fn quarantine_evidence(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<ServiceResolutionForkEvidence>> {
        let mut conn = crate::pg_db(&self.pool);
        let rows = sql_query("SELECT service_id,service_kind,version_id,accepted_digest,conflicting_digest,evidence,quarantined_at FROM service_resolution_fork_quarantine WHERE service_id=$1 AND service_kind=$2 ORDER BY quarantined_at DESC LIMIT $3")
            .bind::<Text,_>(service_id.as_str()).bind::<Text,_>(service_kind)
            .bind::<BigInt,_>(i64::try_from(limit.clamp(1, 256)).unwrap_or(256))
            .load::<QuarantineRow>(&mut conn).await.map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                Ok(ServiceResolutionForkEvidence {
                    service_id: row.service_id,
                    service_kind: row.service_kind,
                    version_id: row.version_id,
                    accepted_digest: Hash::new(row.accepted_digest)
                        .map_err(|error| PersistenceError::Internal(error.to_string()))?,
                    conflicting_digest: Hash::new(row.conflicting_digest)
                        .map_err(|error| PersistenceError::Internal(error.to_string()))?,
                    evidence: row.evidence,
                    quarantined_at: row.quarantined_at,
                })
            })
            .collect()
    }

    async fn method_state(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<ServiceMethodState>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("SELECT method_state AS value FROM service_method_states WHERE service_id=$1 AND service_kind=$2")
            .bind::<Text,_>(service_id.as_str()).bind::<Text,_>(service_kind)
            .get_result::<JsonRow>(&mut conn).await.optional().map_err(PersistenceError::database)?
            .map(|row| decode(row.value)).transpose()
    }

    async fn quarantine_fork(
        &self,
        evidence: ServiceResolutionForkEvidence,
    ) -> PersistenceResult<()> {
        let value = encode(&evidence.evidence)?;
        let mut conn = crate::pg_db(&self.pool);
        sql_query("INSERT INTO service_resolution_fork_quarantine(service_id,service_kind,version_id,accepted_digest,conflicting_digest,evidence,quarantined_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING")
            .bind::<Text,_>(evidence.service_id.as_str()).bind::<Text,_>(&evidence.service_kind).bind::<Text,_>(&evidence.version_id)
            .bind::<Text,_>(evidence.accepted_digest.as_str()).bind::<Text,_>(evidence.conflicting_digest.as_str()).bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(evidence.quarantined_at)
            .execute(&mut conn).await.map_err(PersistenceError::database)?;
        Ok(())
    }

    async fn is_quarantined(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<bool> {
        let mut conn = crate::pg_db(&self.pool);
        Ok(sql_query("SELECT EXISTS(SELECT 1 FROM service_resolution_fork_quarantine WHERE service_id=$1 AND service_kind=$2) AS found")
            .bind::<Text,_>(service_id.as_str()).bind::<Text,_>(service_kind).get_result::<ExistsRow>(&mut conn).await.map_err(PersistenceError::database)?.found)
    }

    async fn route_cache(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<Option<VerifiedServiceRoute>> {
        let mut conn = crate::pg_db(&self.pool);
        // The route cache is a replaceable performance cache that MAY vanish at
        // any time (service-surface.md section 2.6), so a row this build can no
        // longer decode is a cache miss, not a persistence fault. The accepted
        // method-state floor lives in its own table and is never derived here.
        Ok(sql_query("SELECT entry AS value FROM service_route_cache WHERE service_id=$1 AND service_kind=$2")
            .bind::<Text,_>(service_id.as_str()).bind::<Text,_>(service_kind).get_result::<JsonRow>(&mut conn).await.optional().map_err(PersistenceError::database)?
            .and_then(|row| decode::<VerifiedServiceRoute>(row.value).ok()))
    }

    async fn evict_route_cache(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> PersistenceResult<()> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("DELETE FROM service_route_cache WHERE service_id=$1 AND service_kind=$2")
            .bind::<Text, _>(service_id.as_str())
            .bind::<Text, _>(service_kind)
            .execute(&mut conn)
            .await
            .map_err(PersistenceError::database)?;
        Ok(())
    }
    async fn publish_route_cache(
        &self,
        evidence: AuthenticatedServiceResolution,
        route: VerifiedServiceRoute,
    ) -> PersistenceResult<MonotonicRouteWrite> {
        if matches!(
            evidence.method_history_evidence,
            arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog { .. }
        ) {
            arkret_identity::verify_authenticated_service_resolution_history(
                &evidence,
                route.service_id(),
                route.verified_at,
            )
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        }
        if route.cache_expires_at <= route.verified_at || !route.is_routable_at(route.verified_at) {
            return Err(PersistenceError::SchemaViolation(
                "service route cache exceeds current verification lifetime".into(),
            ));
        }
        // The caller may only cache the projection this evidence actually
        // derives; the route carries that projection whole, so the two can only
        // disagree by being different projections.
        if route.projection
            != evidence
                .projection()
                .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?
        {
            return Err(PersistenceError::SchemaViolation(
                "route cache disagrees with DID state".into(),
            ));
        }
        let state = route.method_state();
        let state_value = encode(&state)?;
        let entry_value = encode(&route)?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_,PgTransactionError,_>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))").bind::<Text,_>(format!("service-method:{}:{}",state.service_id,state.service_kind)).execute(conn).await?;
            let current=sql_query("SELECT method_state AS value FROM service_method_states WHERE service_id=$1 AND service_kind=$2 FOR UPDATE").bind::<Text,_>(state.service_id.as_str()).bind::<Text,_>(&state.service_kind).get_result::<JsonRow>(conn).await.optional()?.map(|r|decode::<ServiceMethodState>(r.value)).transpose()?;
            if let Some(current)=current.as_ref() {
                if arkret_identity::verify_service_resolution_floor(&evidence,current).is_err() {
                    let native_fork=match &evidence.method_history_evidence {
                        arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog{log_entries,..}=>{
                            let accepted_index=current.version_id.split('-').next();
                            log_entries.iter().any(|entry|entry.get("versionId").and_then(serde_json::Value::as_str).and_then(|v|v.split('-').next())==accepted_index&&arkret_canonical::canonical_sha256(entry).is_ok_and(|head|head!=current.method_history_head))
                        },_=>false,
                    };
                    if native_fork || (current.version_id==state.version_id && current.method_history_head!=state.method_history_head) {
                        return Ok(MonotonicRouteWrite::Conflict{accepted_digest:Hash::new(current.method_history_head.clone()).map_err(|e|PersistenceError::Internal(e.to_string()))?});
                    }
                    return Ok(MonotonicRouteWrite::Stale);
                }
                if current.verified_at > state.verified_at {
                    // Concurrent verifications can finish in reverse order.
                    // The native floor was checked above; an identical route
                    // may replay without moving its durable clock backwards.
                    let retained = sql_query("SELECT entry AS value FROM service_route_cache WHERE service_id=$1 AND service_kind=$2")
                        .bind::<Text, _>(state.service_id.as_str())
                        .bind::<Text, _>(&state.service_kind)
                        .get_result::<JsonRow>(conn).await.optional()?
                        .and_then(|row| decode::<VerifiedServiceRoute>(row.value).ok());
                    if retained.is_some_and(|cached| cached.projection == route.projection) {
                        return Ok(MonotonicRouteWrite::Replay);
                    }
                    return Ok(MonotonicRouteWrite::Stale);
                }
            }
            sql_query("INSERT INTO service_resolution_histories(service_id,service_kind,evidence,verified_at) VALUES($1,$2,$3,$4) ON CONFLICT(service_id,service_kind) DO UPDATE SET evidence=EXCLUDED.evidence,verified_at=EXCLUDED.verified_at")
                .bind::<Text,_>(state.service_id.as_str()).bind::<Text,_>(&state.service_kind).bind::<Jsonb,_>(encode(&evidence)?).bind::<Timestamptz,_>(state.verified_at).execute(conn).await?;
            sql_query("INSERT INTO service_method_states(service_id,service_kind,method_state,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(service_id,service_kind) DO UPDATE SET method_state=EXCLUDED.method_state,updated_at=EXCLUDED.updated_at").bind::<Text,_>(state.service_id.as_str()).bind::<Text,_>(&state.service_kind).bind::<Jsonb,_>(&state_value).bind::<Timestamptz,_>(state.verified_at).execute(conn).await?;
            sql_query("INSERT INTO service_route_cache(service_id,service_kind,entry,cache_expires_at,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(service_id,service_kind) DO UPDATE SET entry=EXCLUDED.entry,cache_expires_at=EXCLUDED.cache_expires_at,updated_at=EXCLUDED.updated_at").bind::<Text,_>(route.service_id().as_str()).bind::<Text,_>(route.service_kind()).bind::<Jsonb,_>(&entry_value).bind::<Timestamptz,_>(route.cache_expires_at).bind::<Timestamptz,_>(route.verified_at).execute(conn).await?;
            Ok(MonotonicRouteWrite::Applied)
        }).await.map_err(PgTransactionError::into_persistence)
    }
}
