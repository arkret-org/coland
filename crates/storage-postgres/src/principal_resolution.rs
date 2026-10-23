//! Accepted resolution reads and a separately rebuildable query index.
use arkret_wire::{AccountId, Event, RealmId};
use coland_storage::{
    PersistenceError, PersistenceResult, PrincipalResolutionCasResult, PrincipalResolutionRecord,
    PrincipalResolutionStore, validate_principal_resolution_record,
};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncConnection;
use horme::{OptionalExtension, RunQueryDsl};

use crate::{PgPool, PgTransactionError, async_trait, pg_conn};

pub struct PgPrincipalResolutionStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct AppliedRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    applied: bool,
}
#[derive(QueryableByName)]
struct EventRow {
    #[diesel(sql_type = Jsonb)]
    event_json: serde_json::Value,
}

impl PgPrincipalResolutionStore {
    async fn load_by_account_id(
        &self,
        account: &AccountId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        crate::principal_resolution_unit::current_in_connection(&mut conn, Some(account), None)
            .await
            .map(|r| r.map(|r| r.0))
            .map_err(PgTransactionError::into_persistence)
    }
    // CAS repairs a replaceable index; its conflict result must read that index,
    // while every authority-facing read above remains on typed current.
    async fn load_index(
        &self,
        account: &AccountId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        #[derive(diesel::QueryableByName)]
        struct IndexRow {
            #[diesel(sql_type = Text)]
            pcr_realm_id: String,
            #[diesel(sql_type = Jsonb)]
            genesis_event: serde_json::Value,
            #[diesel(sql_type = Jsonb)]
            current_event: serde_json::Value,
            #[diesel(sql_type = Jsonb)]
            projection: serde_json::Value,
        }
        let mut conn = crate::pg_db(&self.pool);
        let row = sql_query("SELECT p.pcr_realm_id,g.event_json AS genesis_event,e.event_json AS current_event,p.projection FROM principal_resolutions p JOIN principal_resolution_events g ON g.principal_id=p.principal_id AND g.station_id=p.station_id AND g.event_id=p.genesis_event_id JOIN principal_resolution_events e ON e.principal_id=p.principal_id AND e.station_id=p.station_id AND e.event_id=p.current_event_id WHERE p.principal_id=$1 AND p.station_id=$2")
            .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
            .get_result::<IndexRow>(&mut conn).await.optional().map_err(PersistenceError::database)?;
        row.map(|row| {
            let record = PrincipalResolutionRecord {
                account_id: account.clone(),
                pcr_realm_id: row
                    .pcr_realm_id
                    .parse()
                    .map_err(|e| PersistenceError::SchemaViolation(format!("{e}")))?,
                genesis_event: serde_json::from_value(row.genesis_event)
                    .map_err(PersistenceError::database)?,
                current_event: serde_json::from_value(row.current_event)
                    .map_err(PersistenceError::database)?,
                projection: serde_json::from_value(row.projection)
                    .map_err(PersistenceError::database)?,
            };
            validate_principal_resolution_record(&record)?;
            Ok(record)
        })
        .transpose()
    }
}

#[async_trait]
impl PrincipalResolutionStore for PgPrincipalResolutionStore {
    async fn admit_update(
        &self,
        write: coland_storage::PrincipalResolutionUpdateWrite,
    ) -> PersistenceResult<arkret_wire::AuthoritySubmitOutcome> {
        write
            .transaction
            .validate()
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::principal_resolution_unit::admit_in_connection(conn, &write).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn registered_genesis(&self, account: &AccountId) -> PersistenceResult<Option<Event>> {
        #[derive(QueryableByName)]
        struct Origin {
            #[diesel(sql_type = Text)]
            realm_id: String,
            #[diesel(sql_type = diesel::sql_types::Binary)]
            exact_request_body: Vec<u8>,
            #[diesel(sql_type = Jsonb)]
            result_json: serde_json::Value,
        }
        let mut conn = pg_conn(&self.pool).await?;
        let row = sql_query("SELECT realm_id,exact_request_body,result_json FROM pcr_genesis_units WHERE principal_id=$1 AND station_id=$2 AND result_json<>'{}'::jsonb")
            .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
            .get_result::<Origin>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let Some(row) = row else { return Ok(None) };
        let realm = row.realm_id.parse().map_err(PersistenceError::database)?;
        let governance =
            crate::pcr_private_authority::accepted_governance(&mut conn, &realm).await?;
        let input: arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput =
            serde_json::from_slice(&row.exact_request_body).map_err(PersistenceError::database)?;
        let outcome: arkret_models_collaboration::principal_operations::PcrGenesisAdmissionOutcome =
            serde_json::from_value(row.result_json).map_err(PersistenceError::database)?;
        outcome
            .validate_against(&input)
            .map_err(PersistenceError::database)?;
        if governance != arkret_wire::GenesisGovernance::Human(account.clone())
            || input.genesis_unit.create().realm_id != realm
        {
            return Err(PersistenceError::SchemaViolation(
                "accepted Human creation differs from Account".into(),
            ));
        }
        Ok(Some(input.genesis_unit.create().clone()))
    }
    async fn current_principal(
        &self,
        account: &AccountId,
    ) -> PersistenceResult<coland_storage::CurrentPrincipalRead> {
        if let Some(record) = self.load_by_account_id(account).await? {
            return Ok(coland_storage::CurrentPrincipalRead::Ready {
                pcr_realm_id: record.pcr_realm_id,
                projection: record.projection,
            });
        }
        let mut conn = crate::pg_db(&self.pool);
        let known=sql_query("SELECT EXISTS(SELECT 1 FROM pcr_genesis_units WHERE principal_id=$1 AND station_id=$2 AND result_json<>'{}'::jsonb) OR EXISTS(SELECT 1 FROM principal_resolution_current_results WHERE principal_id=$1 AND station_id=$2) AS applied")
            .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
            .get_result::<AppliedRow>(&mut conn).await.map_err(PersistenceError::database)?.applied;
        Ok(if known {
            coland_storage::CurrentPrincipalRead::Unavailable
        } else {
            coland_storage::CurrentPrincipalRead::Missing
        })
    }
    async fn by_account_id(
        &self,
        account: &AccountId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        self.load_by_account_id(account).await
    }
    async fn for_realm(
        &self,
        realm: &RealmId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        crate::principal_resolution_unit::current_in_connection(&mut conn, None, Some(realm))
            .await
            .map(|r| r.map(|r| r.0))
            .map_err(PgTransactionError::into_persistence)
    }
    async fn compare_and_set(
        &self,
        expected_current_event_ref: Option<&str>,
        next: PrincipalResolutionRecord,
    ) -> PersistenceResult<PrincipalResolutionCasResult> {
        validate_principal_resolution_record(&next)?;
        let projection = serde_json::to_value(&next.projection)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let current_event = serde_json::to_value(&next.current_event)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let mut conn = crate::pg_db(&self.pool);
        let applied = if let Some(expected) = expected_current_event_ref {
            if expected == next.current_event.event_id.as_str() {
                return Err(PersistenceError::SchemaViolation(
                    "principal resolution CAS cannot rewrite the current Event in place".to_owned(),
                ));
            }
            sql_query(
                "WITH inserted_event AS ( \
                   INSERT INTO principal_resolution_events \
                     (principal_id, station_id, event_id, previous_event_id, method_history_head, event_json, created_at) \
                   SELECT principal_id, station_id, $6, $5, $9, $10, $8 \
                     FROM principal_resolutions \
                    WHERE principal_id = $1 AND station_id = $2 \
                      AND pcr_realm_id = $3 AND genesis_event_id = $4 \
                      AND current_event_id = $5 \
                   ON CONFLICT DO NOTHING \
                   RETURNING principal_id, station_id \
                 ), updated AS ( \
                   UPDATE principal_resolutions current \
                      SET current_event_id = $6, projection = $7, updated_at = $8 \
                     FROM inserted_event \
                    WHERE current.principal_id = inserted_event.principal_id \
                      AND current.station_id = inserted_event.station_id \
                      AND current.current_event_id = $5 \
                    RETURNING current.principal_id \
                 ) \
                 SELECT EXISTS(SELECT 1 FROM updated) AS applied",
            )
            .bind::<Text, _>(next.account_id.principal_id.as_str())
            .bind::<Text, _>(next.account_id.station_id.as_str())
            .bind::<Text, _>(next.pcr_realm_id.as_str())
            .bind::<Text, _>(next.genesis_event.event_id.as_str())
            .bind::<Text, _>(expected)
            .bind::<Text, _>(next.current_event.event_id.as_str())
            .bind::<Jsonb, _>(&projection)
            .bind::<Timestamptz, _>(next.projection.updated_at)
            .bind::<Text, _>(&next.projection.method_history_head)
            .bind::<Jsonb, _>(&current_event)
            .get_result::<AppliedRow>(&mut conn)
            .await
            .map_err(PersistenceError::database)?
            .applied
        } else {
            if next.current_event.event_id != next.genesis_event.event_id {
                return Err(PersistenceError::SchemaViolation(
                    "principal resolution creation must start at its genesis Event".to_owned(),
                ));
            }
            let genesis_event = serde_json::to_value(&next.genesis_event)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?;
            sql_query(
                "WITH inserted AS ( \
                   INSERT INTO principal_resolutions \
                     (principal_id, station_id, pcr_realm_id, genesis_event_id, current_event_id, projection, updated_at) \
                   VALUES ($1, $2, $3, $4, $4, $5, $6) \
                   ON CONFLICT DO NOTHING \
                   RETURNING principal_id, station_id \
                 ), inserted_event AS ( \
                   INSERT INTO principal_resolution_events \
                     (principal_id, station_id, event_id, previous_event_id, method_history_head, event_json, created_at) \
                   SELECT principal_id, station_id, $4, NULL, $7, $8, $6 FROM inserted \
                 ) \
                 SELECT EXISTS(SELECT 1 FROM inserted) AS applied",
            )
            .bind::<Text, _>(next.account_id.principal_id.as_str())
            .bind::<Text, _>(next.account_id.station_id.as_str())
            .bind::<Text, _>(next.pcr_realm_id.as_str())
            .bind::<Text, _>(next.genesis_event.event_id.as_str())
            .bind::<Jsonb, _>(&projection)
            .bind::<Timestamptz, _>(next.projection.updated_at)
            .bind::<Text, _>(&next.projection.method_history_head)
            .bind::<Jsonb, _>(&genesis_event)
            .get_result::<AppliedRow>(&mut conn)
            .await
            .map_err(PersistenceError::database)?
            .applied
        };

        if applied {
            Ok(PrincipalResolutionCasResult::Applied(next))
        } else {
            Ok(PrincipalResolutionCasResult::Conflict(
                self.load_index(&next.account_id).await?,
            ))
        }
    }

    async fn history_newest_first(
        &self,
        account: &AccountId,
        after: Option<&str>,
        limit: usize,
    ) -> PersistenceResult<Vec<Event>> {
        let mut conn = crate::pg_db(&self.pool);
        let rows=sql_query("WITH RECURSIVE chain AS ( \
            SELECT c.commit_json,e.envelope AS event_json,0::bigint AS depth \
            FROM principal_resolution_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id AND c.stream_position=r.current_stream_position AND c.realm_id=r.pcr_realm_id \
            JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE r.principal_id=$1 AND r.station_id=$2 \
            UNION ALL \
            SELECT c.commit_json,e.envelope,chain.depth+1 FROM chain \
            JOIN realm_commits c ON c.commit_id=chain.event_json #>> '{payload,expected_revision,commit_id}' \
              AND c.stream_position=(chain.event_json #>> '{payload,expected_revision,stream_position}')::bigint \
              AND c.realm_id=chain.event_json->>'realm_id' \
            JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' AND e.envelope->'actor_id'=chain.event_json->'actor_id' \
              AND e.kind IN ('ak.realm.create','ak.identity.resolution.update') \
            WHERE chain.event_json->>'kind'='ak.identity.resolution.update' \
        ) SELECT event_json FROM chain WHERE $3::text IS NULL OR depth>(SELECT depth FROM chain WHERE event_json->>'event_id'=$3) ORDER BY depth LIMIT $4")
            .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
            .bind::<Nullable<Text>,_>(after).bind::<BigInt,_>(i64::try_from(limit).unwrap_or(i64::MAX))
            .load::<EventRow>(&mut conn).await.map_err(PersistenceError::database)?;
        if after.is_some() && rows.is_empty() {
            // Genesis is a legitimate exclusive ancestor with no predecessor.
            let record = self.load_by_account_id(account).await?;
            if record.as_ref().map(|r| r.genesis_event.event_id.as_str()) != after {
                return Err(PersistenceError::NotFound(
                    "resolution history ancestor unknown".into(),
                ));
            }
        }
        rows.into_iter()
            .map(|row| serde_json::from_value(row.event_json).map_err(PersistenceError::database))
            .collect()
    }
}
