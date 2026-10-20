use arkret_models_crypto::{PeerKeyPackageRequesterAuthorization, PeerKeyPackagesClaimRequestBody};
use coland_storage::{PeerKeyPackageClaimRateDecision, PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncConnection, RunQueryDsl};

use crate::{PgPool, PgTransactionError, pg_conn};

#[derive(QueryableByName)]
struct Attempt {
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Nullable<Text>)]
    rejection_reason: Option<String>,
}

#[derive(QueryableByName)]
struct Clock {
    #[diesel(sql_type = Timestamptz)]
    now: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

// The handler has already authenticated both layers. Only the SDK command
// reaches this boundary; callers cannot choose a reduced identity or digest.
pub(crate) async fn record_attempt(
    pool: &PgPool,
    body: &PeerKeyPackagesClaimRequestBody,
) -> PersistenceResult<PeerKeyPackageClaimRateDecision> {
    body.validate_shape()
        .map_err(|error| PersistenceError::Conflict(format!("claim budget shape: {error}")))?;
    let requester = match (&body.requester_account_id, &body.requester_authorization) {
        (Some(account), PeerKeyPackageRequesterAuthorization::Device { .. }) => {
            format!(
                "account:{}",
                account
                    .canonical_key()
                    .map_err(PersistenceError::database)?
            )
        }
        (
            None,
            PeerKeyPackageRequesterAuthorization::Agent {
                requester_agent_id, ..
            },
        ) => {
            format!("agent:{requester_agent_id}")
        }
        (None, PeerKeyPackageRequesterAuthorization::RealmDevice { .. }) => {
            let actor = body
                .requester_actor_id
                .as_ref()
                .ok_or_else(|| PersistenceError::Conflict("Realm requester absent".into()))?;
            format!(
                "realm:{}",
                arkret_canonical::canonical_json_string(actor)
                    .map_err(PersistenceError::database)?
            )
        }
        _ => {
            return Err(PersistenceError::Conflict(
                "claim budget requester branch".into(),
            ));
        }
    };
    let target = match (&body.target_account_id, &body.target_agent_id) {
        (Some(account), None) => format!(
            "account:{}",
            account
                .canonical_key()
                .map_err(PersistenceError::database)?
        ),
        (None, Some(agent)) => format!("agent:{agent}"),
        (None, None) if body.target_actor_id.is_some() => {
            format!(
                "realm:{}",
                arkret_canonical::canonical_json_string(body.target_actor_id.as_ref().unwrap())
                    .map_err(PersistenceError::database)?
            )
        }
        _ => {
            return Err(PersistenceError::Conflict(
                "claim budget target branch".into(),
            ));
        }
    };
    let requester =
        arkret_canonical::canonical_sha256(&requester).map_err(PersistenceError::database)?;
    let target = arkret_canonical::canonical_sha256(&target).map_err(PersistenceError::database)?;
    let signed_at = match &body.requester_authorization {
        PeerKeyPackageRequesterAuthorization::Device { signed_at, .. }
        | PeerKeyPackageRequesterAuthorization::Agent { signed_at, .. }
        | PeerKeyPackageRequesterAuthorization::RealmDevice { signed_at, .. } => *signed_at,
    };
    let source = body.service_binding.source_id.as_str();
    let identity = body.claim_request_id.as_str();
    let digest = arkret_canonical::canonical_sha256(body).map_err(PersistenceError::database)?;
    let source_target = arkret_canonical::canonical_sha256(&[source, &target])
        .map_err(PersistenceError::database)?;
    let transaction = arkret_canonical::canonical_json_string(&[source, identity])
        .map_err(PersistenceError::database)?;
    let mut locks = [
        format!("keypackage-claim-budget:requester:{requester}"),
        format!("keypackage-claim-budget:target:{target}"),
        format!("keypackage-claim-budget:source-target:{source_target}"),
        format!("keypackage-claim-budget:transaction:{transaction}"),
    ];
    locks.sort();
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        for key in locks {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind::<Text,_>(key).execute(&mut *conn).await.map_err(PersistenceError::database)?;
        }
        // Evaluate after acquiring all writer locks. Process clocks, startup
        // hydration and key rotation cannot reset a shared identity's budget.
        let now = sql_query("SELECT clock_timestamp() AS now").get_result::<Clock>(&mut *conn).await.map_err(PersistenceError::database)?.now;
        if body.expires_at <= now || signed_at > now + chrono::Duration::seconds(60)
            || body.expires_at <= signed_at || body.expires_at - signed_at > chrono::Duration::seconds(300) {
            return Ok(PeerKeyPackageClaimRateDecision::Unavailable);
        }
        sql_query("DELETE FROM keypackage_claim_attempts WHERE expires_at<=$1")
            .bind::<Timestamptz,_>(now).execute(&mut *conn).await.map_err(PersistenceError::database)?;
        if let Some(existing) = sql_query("SELECT request_digest,rejection_reason FROM keypackage_claim_attempts WHERE source_id=$1 AND claim_request_id=$2")
            .bind::<Text,_>(source).bind::<Text,_>(identity).get_result::<Attempt>(&mut *conn).await.optional().map_err(PersistenceError::database)? {
            return Ok(if existing.request_digest != digest { PeerKeyPackageClaimRateDecision::DuplicateConflict }
                else if existing.rejection_reason.is_none() { PeerKeyPackageClaimRateDecision::Allowed }
                else { PeerKeyPackageClaimRateDecision::RateLimited });
        }
        let since = now - chrono::Duration::seconds(60);
        let mut allowed = true;
        for (column, key) in [("requester_identity", requester.as_str()), ("target_identity", target.as_str()), ("source_target_identity", source_target.as_str())] {
            // All identifiers are compile-time closed literals above.
            let count = sql_query(format!("SELECT COUNT(*) AS count FROM keypackage_claim_attempts WHERE {column}=$1 AND attempted_at>$2"))
                .bind::<Text,_>(key).bind::<Timestamptz,_>(since).get_result::<Count>(&mut *conn).await.map_err(PersistenceError::database)?.count;
            allowed &= count < 5;
        }
        sql_query("INSERT INTO keypackage_claim_attempts(source_id,claim_request_id,request_digest,requester_identity,target_identity,source_target_identity,rejection_reason,attempted_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind::<Text,_>(source).bind::<Text,_>(identity).bind::<Text,_>(&digest).bind::<Text,_>(&requester).bind::<Text,_>(&target).bind::<Text,_>(&source_target)
            .bind::<Nullable<Text>,_>(if allowed { None } else { Some("keypackage_claim_rate_limited") }).bind::<Timestamptz,_>(now).bind::<Timestamptz,_>(body.expires_at + chrono::Duration::minutes(10))
            .execute(&mut *conn).await.map_err(PersistenceError::database)?;
        Ok(if allowed { PeerKeyPackageClaimRateDecision::Allowed } else { PeerKeyPackageClaimRateDecision::RateLimited })
    }).await.map_err(|error| error.into_persistence())
}

pub(crate) async fn prune(pool: &PgPool) -> PersistenceResult<usize> {
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    sql_query("DELETE FROM keypackage_claim_attempts WHERE expires_at<=clock_timestamp()")
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)
}
