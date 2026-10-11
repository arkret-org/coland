use arkret_models_identity::PrincipalResolutionProjection;
use arkret_wire::{AccountId, DidCoreId, Event, RealmId};
use coland_storage::{
    PersistenceError, PersistenceResult, PrincipalResolutionCasResult, PrincipalResolutionRecord,
    PrincipalResolutionStore, validate_principal_resolution_record,
};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::RunQueryDsl;

use crate::{PgPool, async_trait, pg_conn};

pub struct PgPrincipalResolutionStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct CurrentRow {
    #[diesel(sql_type = Text)]
    principal_id: DidCoreId,
    #[diesel(sql_type = Text)]
    station_id: DidCoreId,
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
    #[diesel(sql_type = Jsonb)]
    genesis_event: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    current_event: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    projection: serde_json::Value,
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

#[derive(QueryableByName)]
struct GenesisAnchorRow {
    #[diesel(sql_type = Text)]
    principal_id: DidCoreId,
    #[diesel(sql_type = Text)]
    station_id: DidCoreId,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    result_json: serde_json::Value,
}

#[derive(QueryableByName)]
struct EnvelopeRow {
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

/// Which immutable creation anchor to rebuild the index row from.
enum GenesisAnchor<'a> {
    Account(&'a AccountId),
    Realm(&'a RealmId),
}

/// Outcome of rebuilding one missing index row from durable PCR lineage.
enum IndexRebuild {
    /// The account has no accepted human PCR genesis on this Station.
    NoAnchor,
    /// The row is present again.
    Present,
    /// An accepted `ak.identity.resolution.update` succeeds the genesis, so
    /// the initial resolution is not the current one and cannot stand in for it.
    CurrentUndecided,
}

impl TryFrom<CurrentRow> for PrincipalResolutionRecord {
    type Error = PersistenceError;

    fn try_from(row: CurrentRow) -> Result<Self, Self::Error> {
        let record = Self {
            account_id: AccountId::new(row.principal_id, row.station_id),
            pcr_realm_id: RealmId::new(row.pcr_realm_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            genesis_event: serde_json::from_value(row.genesis_event)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            current_event: serde_json::from_value(row.current_event)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            projection: serde_json::from_value::<PrincipalResolutionProjection>(row.projection)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        };
        validate_principal_resolution_record(&record)?;
        Ok(record)
    }
}

impl PgPrincipalResolutionStore {
    async fn load_by_account_id(
        &self,
        account_id: &AccountId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT p.principal_id, p.station_id, p.pcr_realm_id, \
                    genesis.event_json AS genesis_event, current.event_json AS current_event, \
                    p.projection \
             FROM principal_resolutions p \
             JOIN principal_resolution_events genesis \
               ON genesis.principal_id = p.principal_id \
              AND genesis.station_id = p.station_id \
              AND genesis.event_id = p.genesis_event_id \
             JOIN principal_resolution_events current \
               ON current.principal_id = p.principal_id \
              AND current.station_id = p.station_id \
              AND current.event_id = p.current_event_id \
             WHERE p.principal_id = $1 AND p.station_id = $2",
        )
        .bind::<Text, _>(account_id.principal_id.as_str())
        .bind::<Text, _>(account_id.station_id.as_str())
        .get_result::<CurrentRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(PrincipalResolutionRecord::try_from)
        .transpose()
    }

    async fn load_for_realm(
        &self,
        pcr_realm_id: &RealmId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT p.principal_id, p.station_id, p.pcr_realm_id, \
                    genesis.event_json AS genesis_event, current.event_json AS current_event, \
                    p.projection \
             FROM principal_resolutions p \
             JOIN principal_resolution_events genesis \
               ON genesis.principal_id = p.principal_id \
              AND genesis.station_id = p.station_id \
              AND genesis.event_id = p.genesis_event_id \
             JOIN principal_resolution_events current \
               ON current.principal_id = p.principal_id \
              AND current.station_id = p.station_id \
              AND current.event_id = p.current_event_id \
             WHERE p.pcr_realm_id = $1",
        )
        .bind::<Text, _>(pcr_realm_id.as_str())
        .get_result::<CurrentRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(PrincipalResolutionRecord::try_from)
        .transpose()
    }
}

impl PgPrincipalResolutionStore {
    /// Rebuild the replaceable index row of one human PCR from its immutable
    /// creation anchor: the accepted genesis unit, its committed
    /// `ak.realm.create` and the initial resolution it committed in the same
    /// transaction (`identity-did.md` §4.2.3, derived cache recovery). An
    /// accepted resolution successor leaves the row missing: its current
    /// projection needs the method-verified successor, never the genesis.
    async fn rebuild_from_genesis_anchor(
        &self,
        anchor: GenesisAnchor<'_>,
    ) -> PersistenceResult<IndexRebuild> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let query = match anchor {
            GenesisAnchor::Account(account_id) => sql_query(
                "SELECT principal_id, station_id, realm_id, result_json FROM pcr_genesis_units \
                 WHERE principal_id = $1 AND station_id = $2 AND result_json <> '{}'::jsonb",
            )
            .into_boxed()
            .bind::<Text, _>(account_id.principal_id.as_str())
            .bind::<Text, _>(account_id.station_id.as_str()),
            GenesisAnchor::Realm(realm_id) => sql_query(
                "SELECT principal_id, station_id, realm_id, result_json FROM pcr_genesis_units \
                 WHERE realm_id = $1 AND result_json <> '{}'::jsonb",
            )
            .into_boxed()
            .bind::<Text, _>(realm_id.as_str()),
        };
        let Some(row) = query
            .get_result::<GenesisAnchorRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
        else {
            return Ok(IndexRebuild::NoAnchor);
        };
        let result = serde_json::from_value::<
            arkret_models_collaboration::principal_operations::PcrGenesisAdmissionOutcome,
        >(row.result_json)
        .map_err(|error| {
            PersistenceError::Internal(format!("stored PCR genesis result is invalid: {error}"))
        })?;
        let pcr_realm_id = RealmId::new(row.realm_id)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let successors = sql_query(
            "SELECT count(*) AS count FROM canonical_events e \
             JOIN realm_commits c ON c.event_pk = e.pk \
             WHERE e.realm_id = $1 AND e.kind = $2 AND e.state = 'committed'",
        )
        .bind::<Text, _>(pcr_realm_id.as_str())
        .bind::<Text, _>(arkret_wire::EventKind::IdentityResolutionUpdate.as_str())
        .get_result::<CountRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .count;
        if successors > 0 {
            return Ok(IndexRebuild::CurrentUndecided);
        }
        let genesis_event_id = &result.commits[0].event_ref;
        let token = crate::ids::parse_event_id(genesis_event_id.as_str()).ok_or_else(|| {
            PersistenceError::Internal("stored PCR genesis Event id is not canonical".to_owned())
        })?;
        let envelope = sql_query(
            "SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk = e.pk \
             WHERE e.id = $1 AND e.realm_id = $2 AND e.state = 'committed'",
        )
        .bind::<diesel::sql_types::Binary, _>(token.to_vec())
        .bind::<Text, _>(pcr_realm_id.as_str())
        .get_result::<EnvelopeRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| {
            PersistenceError::Internal("accepted PCR genesis has no committed Event".to_owned())
        })?
        .envelope;
        let genesis_event = serde_json::from_value::<Event>(envelope)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        drop(conn);
        let record = PrincipalResolutionRecord {
            account_id: AccountId::new(row.principal_id, row.station_id),
            pcr_realm_id,
            current_event: genesis_event.clone(),
            genesis_event,
            projection: result.resolution,
        };
        match self.compare_and_set(None, record).await? {
            PrincipalResolutionCasResult::Applied(_) => Ok(IndexRebuild::Present),
            PrincipalResolutionCasResult::Conflict(Some(_)) => Ok(IndexRebuild::Present),
            PrincipalResolutionCasResult::Conflict(None) => Err(PersistenceError::Conflict(
                "principal resolution index rebuild lost its genesis row".to_owned(),
            )),
        }
    }

    /// The index row for `account_id`, rebuilt from the account's immutable
    /// creation anchor when it was evicted.
    async fn indexed_by_account_id(
        &self,
        account_id: &AccountId,
    ) -> PersistenceResult<Result<Option<PrincipalResolutionRecord>, IndexRebuild>> {
        if let Some(record) = self.load_by_account_id(account_id).await? {
            return Ok(Ok(Some(record)));
        }
        match self
            .rebuild_from_genesis_anchor(GenesisAnchor::Account(account_id))
            .await?
        {
            IndexRebuild::Present => Ok(Ok(self.load_by_account_id(account_id).await?)),
            IndexRebuild::NoAnchor => Ok(Ok(None)),
            undecided @ IndexRebuild::CurrentUndecided => Ok(Err(undecided)),
        }
    }
}

fn current_undecided() -> PersistenceError {
    PersistenceError::Internal(
        "the PCR identity resolution current is not available from its creation anchor".to_owned(),
    )
}

#[async_trait]
impl PrincipalResolutionStore for PgPrincipalResolutionStore {
    async fn current_principal(
        &self,
        account_id: &AccountId,
    ) -> PersistenceResult<coland_storage::CurrentPrincipalRead> {
        Ok(match self.indexed_by_account_id(account_id).await? {
            Ok(Some(record)) => coland_storage::CurrentPrincipalRead::Ready {
                pcr_realm_id: record.pcr_realm_id,
                projection: record.projection,
            },
            Ok(None) => coland_storage::CurrentPrincipalRead::Missing,
            Err(_) => coland_storage::CurrentPrincipalRead::Unavailable,
        })
    }
    async fn by_account_id(
        &self,
        account_id: &AccountId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        self.indexed_by_account_id(account_id)
            .await?
            .map_err(|_| current_undecided())
    }

    async fn for_realm(
        &self,
        pcr_realm_id: &RealmId,
    ) -> PersistenceResult<Option<PrincipalResolutionRecord>> {
        if let Some(record) = self.load_for_realm(pcr_realm_id).await? {
            return Ok(Some(record));
        }
        match self
            .rebuild_from_genesis_anchor(GenesisAnchor::Realm(pcr_realm_id))
            .await?
        {
            IndexRebuild::Present => self.load_for_realm(pcr_realm_id).await,
            IndexRebuild::NoAnchor => Ok(None),
            IndexRebuild::CurrentUndecided => Err(current_undecided()),
        }
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
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
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
            .get_result::<AppliedRow>(&mut *conn)
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
            .get_result::<AppliedRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
            .applied
        };

        if applied {
            Ok(PrincipalResolutionCasResult::Applied(next))
        } else {
            Ok(PrincipalResolutionCasResult::Conflict(
                self.load_by_account_id(&next.account_id).await?,
            ))
        }
    }

    async fn history_newest_first(
        &self,
        account_id: &AccountId,
        after_event_ref: Option<&str>,
        limit: usize,
    ) -> PersistenceResult<Vec<Event>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        if let Some(after) = after_event_ref {
            let exists = sql_query(
                "SELECT EXISTS(SELECT 1 FROM principal_resolution_events \
                  WHERE principal_id = $1 AND station_id = $2 AND event_id = $3) AS applied",
            )
            .bind::<Text, _>(account_id.principal_id.as_str())
            .bind::<Text, _>(account_id.station_id.as_str())
            .bind::<Text, _>(after)
            .get_result::<AppliedRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?
            .applied;
            if !exists {
                return Err(PersistenceError::NotFound(format!(
                    "principal resolution history cursor {after}"
                )));
            }
        }

        let rows = sql_query(
            "WITH RECURSIVE chain AS ( \
               SELECT event.event_json, event.previous_event_id, 0::bigint AS depth \
                 FROM principal_resolution_events event \
                 JOIN principal_resolutions current \
                   ON current.principal_id = event.principal_id \
                  AND current.station_id = event.station_id \
                WHERE event.principal_id = $1 AND event.station_id = $2 \
                  AND event.event_id = COALESCE($3, current.current_event_id) \
               UNION ALL \
               SELECT predecessor.event_json, predecessor.previous_event_id, chain.depth + 1 \
                 FROM chain \
                 JOIN principal_resolution_events predecessor \
                   ON predecessor.principal_id = $1 \
                  AND predecessor.station_id = $2 \
                  AND predecessor.event_id = chain.previous_event_id \
             ) \
             SELECT event_json FROM chain \
              WHERE $3 IS NULL OR depth > 0 \
              ORDER BY depth ASC \
              LIMIT $4",
        )
        .bind::<Text, _>(account_id.principal_id.as_str())
        .bind::<Text, _>(account_id.station_id.as_str())
        .bind::<Nullable<Text>, _>(after_event_ref)
        .bind::<BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .load::<EventRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        rows.into_iter()
            .map(|row| {
                serde_json::from_value(row.event_json)
                    .map_err(|error| PersistenceError::Internal(error.to_string()))
            })
            .collect()
    }
}
