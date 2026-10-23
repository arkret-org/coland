use std::collections::BTreeMap;

use arkret_models_identity::{OrganizationRegistrationChallenge, OrganizationRegistrationOutcome};
use arkret_wire::{DidCoreId, Hash};
use coland_storage::{
    OrganizationRegistrationChallengeRecord, OrganizationRegistrationCurrent,
    OrganizationRegistrationEnsureCommit, OrganizationRegistrationGenerationRecord,
    OrganizationRegistrationLifecycleCommit, OrganizationRegistrationRefreshCommit,
    OrganizationRegistrationStateRecord, OrganizationRegistrationStore,
    OrganizationRegistrationTerminalReason, PersistenceError, PersistenceResult,
    apply_organization_registration_ensure, apply_organization_registration_lifecycle,
    apply_organization_registration_refresh, apply_organization_registration_stale,
    validate_prepared_challenge,
};

use super::{
    AsyncConnection, BigInt, Jsonb, Nullable, OptionalExtension, PgPool, PgTransactionError,
    QueryableByName, RunQueryDsl, Text, Timestamptz, Value, async_trait, pg_conn, sql_query,
};

pub struct PgOrganizationRegistrationStore {
    pub pool: PgPool,
}

impl PgOrganizationRegistrationStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(QueryableByName)]
struct ChallengeRow {
    #[diesel(sql_type = Text)]
    challenge_id: String,
    #[diesel(sql_type = Text)]
    organization_id: DidCoreId,
    #[diesel(sql_type = Jsonb)]
    record: Value,
    #[diesel(sql_type = Nullable<Text>)]
    consumed_request_digest: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    consumed_outcome_id: Option<String>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    consumed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl TryFrom<ChallengeRow> for OrganizationRegistrationChallengeRecord {
    type Error = PersistenceError;

    fn try_from(row: ChallengeRow) -> Result<Self, Self::Error> {
        let record: OrganizationRegistrationChallengeRecord = serde_json::from_value(row.record)
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "organization registration challenge row: {error}"
                ))
            })?;
        validate_prepared_challenge(&record.challenge)?;
        if record.challenge.challenge_id != row.challenge_id
            || record.challenge.organization_id != row.organization_id
            || record.consumed_request_digest.as_ref().map(Hash::as_str)
                != row.consumed_request_digest.as_deref()
            || record.consumed_outcome_id != row.consumed_outcome_id
            || record.consumed_at != row.consumed_at
        {
            return Err(PersistenceError::Internal(
                "organization registration challenge row key mismatch".to_owned(),
            ));
        }
        Ok(record)
    }
}

#[derive(QueryableByName)]
struct StateRow {
    #[diesel(sql_type = Text)]
    organization_id: DidCoreId,
    #[diesel(sql_type = BigInt)]
    current_generation: i64,
    #[diesel(sql_type = Text)]
    current_outcome_id: String,
    #[diesel(sql_type = Jsonb)]
    state: Value,
}

impl TryFrom<StateRow> for OrganizationRegistrationStateRecord {
    type Error = PersistenceError;

    fn try_from(row: StateRow) -> Result<Self, Self::Error> {
        let state: OrganizationRegistrationStateRecord = serde_json::from_value(row.state)
            .map_err(|error| {
                PersistenceError::Internal(format!("organization registration state row: {error}"))
            })?;
        state.validate()?;
        let current = state.current()?;
        if state.organization_id != row.organization_id
            || i64::try_from(state.current_generation).ok() != Some(row.current_generation)
            || current.current_outcome_id != row.current_outcome_id
        {
            return Err(PersistenceError::Internal(
                "organization registration state row key mismatch".to_owned(),
            ));
        }
        Ok(state)
    }
}

#[derive(QueryableByName)]
struct OutcomeRow {
    #[diesel(sql_type = Text)]
    outcome_id: String,
    #[diesel(sql_type = Text)]
    organization_id: DidCoreId,
    #[diesel(sql_type = BigInt)]
    registration_generation: i64,
    #[diesel(sql_type = Jsonb)]
    outcome: Value,
}

impl TryFrom<OutcomeRow> for OrganizationRegistrationOutcome {
    type Error = PersistenceError;

    fn try_from(row: OutcomeRow) -> Result<Self, Self::Error> {
        let outcome: OrganizationRegistrationOutcome = serde_json::from_value(row.outcome)
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "organization registration outcome row: {error}"
                ))
            })?;
        outcome
            .validate()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        if outcome.registration_receipt.registration_receipt_id != row.outcome_id
            || outcome.registration_receipt.organization_id != row.organization_id
            || i64::try_from(outcome.registration_receipt.registration_generation).ok()
                != Some(row.registration_generation)
        {
            return Err(PersistenceError::Internal(
                "organization registration outcome row key mismatch".to_owned(),
            ));
        }
        Ok(outcome)
    }
}

#[async_trait]
impl OrganizationRegistrationStore for PgOrganizationRegistrationStore {
    async fn prepare_challenge(
        &self,
        challenge: OrganizationRegistrationChallenge,
    ) -> PersistenceResult<OrganizationRegistrationChallengeRecord> {
        validate_prepared_challenge(&challenge)?;
        let record = OrganizationRegistrationChallengeRecord::prepared(challenge);
        let value = serde_json::to_value(&record)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let mut conn = crate::pg_db(&self.pool);
        let inserted = sql_query(
            "INSERT INTO organization_registration_challenges \
             (challenge_id, organization_id, record, expires_at, created_at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (challenge_id) DO NOTHING",
        )
        .bind::<Text, _>(&record.challenge.challenge_id)
        .bind::<Text, _>(&record.challenge.organization_id)
        .bind::<Jsonb, _>(&value)
        .bind::<Timestamptz, _>(record.challenge.expires_at)
        .bind::<Timestamptz, _>(record.challenge.created_at)
        .execute(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        if inserted == 0 {
            return Err(PersistenceError::Conflict(
                "organization registration prepare challenge id already exists".to_owned(),
            ));
        }
        Ok(record)
    }

    async fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> PersistenceResult<Option<OrganizationRegistrationChallengeRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_challenge(&mut conn, challenge_id, false).await
    }

    async fn get_current(
        &self,
        organization_id: &DidCoreId,
    ) -> PersistenceResult<Option<OrganizationRegistrationCurrent>> {
        let mut conn = pg_conn(&self.pool).await?;
        let Some(state) = load_state(&mut conn, organization_id, false).await? else {
            return Ok(None);
        };
        let generation = state.current()?.clone();
        let outcome = load_outcome(&mut conn, &generation.current_outcome_id)
            .await?
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "organization registration current outcome is missing".to_owned(),
                )
            })?;
        Ok(Some(OrganizationRegistrationCurrent {
            generation,
            outcome,
        }))
    }

    async fn get_generation(
        &self,
        organization_id: &DidCoreId,
        generation: u64,
    ) -> PersistenceResult<Option<OrganizationRegistrationGenerationRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        Ok(load_state(&mut conn, organization_id, false)
            .await?
            .and_then(|state| state.generations.get(&generation).cloned()))
    }

    async fn get_outcome(
        &self,
        outcome_id: &str,
    ) -> PersistenceResult<Option<OrganizationRegistrationOutcome>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_outcome(&mut conn, outcome_id).await
    }

    async fn ensure(
        &self,
        commit: OrganizationRegistrationEnsureCommit,
    ) -> PersistenceResult<OrganizationRegistrationOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let mut challenge = load_challenge(conn, &commit.challenge_id, true)
                .await?
                .ok_or_else(challenge_not_found)?;
            lock_organization(conn, &challenge.challenge.organization_id).await?;
            let organization_id = challenge.challenge.organization_id.clone();
            let mut state = load_state(conn, &organization_id, true).await?;
            let mut outcomes = load_organization_outcomes(conn, &organization_id).await?;
            let outcome = apply_organization_registration_ensure(
                &mut challenge,
                &mut state,
                &mut outcomes,
                commit,
            )?;
            persist_outcomes(conn, &outcomes, outcome.registration_receipt.issued_at).await?;
            let state = state.expect("successful ensure always leaves registration state");
            persist_state(conn, &state).await?;
            persist_challenge(conn, &challenge).await?;
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn refresh(
        &self,
        commit: OrganizationRegistrationRefreshCommit,
    ) -> PersistenceResult<OrganizationRegistrationOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let mut challenge = load_challenge(conn, &commit.challenge_id, true)
                .await?
                .ok_or_else(challenge_not_found)?;
            lock_organization(conn, &challenge.challenge.organization_id).await?;
            let organization_id = challenge.challenge.organization_id.clone();
            let mut state = load_state(conn, &organization_id, true)
                .await?
                .ok_or_else(|| {
                    PersistenceError::NotFound("organization registration".to_owned())
                })?;
            let mut outcomes = load_organization_outcomes(conn, &organization_id).await?;
            let outcome = apply_organization_registration_refresh(
                &mut challenge,
                &mut state,
                &mut outcomes,
                commit,
            )?;
            persist_outcomes(conn, &outcomes, outcome.registration_receipt.issued_at).await?;
            persist_state(conn, &state).await?;
            persist_challenge(conn, &challenge).await?;
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn mark_stale(
        &self,
        organization_id: &DidCoreId,
        expected_current_generation: u64,
        expected_current_outcome_id: &str,
        changed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<OrganizationRegistrationCurrent> {
        let organization_id = organization_id.clone();
        let expected_current_outcome_id = expected_current_outcome_id.to_owned();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            lock_organization(conn, &organization_id).await?;
            let mut state = load_state(conn, &organization_id, true)
                .await?
                .ok_or_else(|| {
                    PersistenceError::NotFound("organization registration".to_owned())
                })?;
            let outcomes = load_organization_outcomes(conn, &organization_id).await?;
            let current = apply_organization_registration_stale(
                &mut state,
                &outcomes,
                &organization_id,
                expected_current_generation,
                &expected_current_outcome_id,
                changed_at,
            )?;
            persist_state(conn, &state).await?;
            Ok(current)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn revoke(
        &self,
        commit: OrganizationRegistrationLifecycleCommit,
    ) -> PersistenceResult<OrganizationRegistrationOutcome> {
        self.apply_lifecycle(commit, None).await
    }

    async fn deactivate(
        &self,
        commit: OrganizationRegistrationLifecycleCommit,
    ) -> PersistenceResult<OrganizationRegistrationOutcome> {
        self.apply_lifecycle(
            commit,
            Some(OrganizationRegistrationTerminalReason::ExternalDidDeactivated),
        )
        .await
    }
}

impl PgOrganizationRegistrationStore {
    async fn apply_lifecycle(
        &self,
        commit: OrganizationRegistrationLifecycleCommit,
        required_reason: Option<OrganizationRegistrationTerminalReason>,
    ) -> PersistenceResult<OrganizationRegistrationOutcome> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            lock_organization(conn, &commit.organization_id).await?;
            let mut state = load_state(conn, &commit.organization_id, true)
                .await?
                .ok_or_else(|| {
                    PersistenceError::NotFound("organization registration".to_owned())
                })?;
            let mut outcomes = load_organization_outcomes(conn, &commit.organization_id).await?;
            let outcome = apply_organization_registration_lifecycle(
                &mut state,
                &mut outcomes,
                commit,
                required_reason,
            )?;
            persist_outcomes(conn, &outcomes, outcome.registration_receipt.issued_at).await?;
            persist_state(conn, &state).await?;
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

async fn lock_organization(
    conn: &mut diesel_async::AsyncPgConnection,
    organization_id: &DidCoreId,
) -> PersistenceResult<()> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(&format!("organization-registration:{organization_id}"))
        .execute(conn)
        .await
        .map(|_| ())
        .map_err(PersistenceError::database)
}

async fn load_challenge(
    conn: &mut diesel_async::AsyncPgConnection,
    challenge_id: &str,
    for_update: bool,
) -> PersistenceResult<Option<OrganizationRegistrationChallengeRecord>> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    sql_query(format!(
        "SELECT challenge_id, organization_id, record, consumed_request_digest, \
            consumed_outcome_id, consumed_at \
         FROM organization_registration_challenges WHERE challenge_id = $1{suffix}"
    ))
    .bind::<Text, _>(challenge_id)
    .get_result::<ChallengeRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(OrganizationRegistrationChallengeRecord::try_from)
    .transpose()
}

async fn load_state(
    conn: &mut diesel_async::AsyncPgConnection,
    organization_id: &DidCoreId,
    for_update: bool,
) -> PersistenceResult<Option<OrganizationRegistrationStateRecord>> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    sql_query(format!(
        "SELECT organization_id, current_generation, current_outcome_id, state \
         FROM organization_registration_states WHERE organization_id = $1{suffix}"
    ))
    .bind::<Text, _>(organization_id)
    .get_result::<StateRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(OrganizationRegistrationStateRecord::try_from)
    .transpose()
}

async fn load_outcome(
    conn: &mut diesel_async::AsyncPgConnection,
    outcome_id: &str,
) -> PersistenceResult<Option<OrganizationRegistrationOutcome>> {
    sql_query(
        "SELECT outcome_id, organization_id, registration_generation, outcome \
         FROM organization_registration_outcomes WHERE outcome_id = $1",
    )
    .bind::<Text, _>(outcome_id)
    .get_result::<OutcomeRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .map(OrganizationRegistrationOutcome::try_from)
    .transpose()
}

async fn load_organization_outcomes(
    conn: &mut diesel_async::AsyncPgConnection,
    organization_id: &DidCoreId,
) -> PersistenceResult<BTreeMap<String, OrganizationRegistrationOutcome>> {
    let rows = sql_query(
        "SELECT outcome_id, organization_id, registration_generation, outcome \
         FROM organization_registration_outcomes WHERE organization_id = $1",
    )
    .bind::<Text, _>(organization_id)
    .load::<OutcomeRow>(conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut outcomes = BTreeMap::new();
    for row in rows {
        let id = row.outcome_id.clone();
        outcomes.insert(id, OrganizationRegistrationOutcome::try_from(row)?);
    }
    Ok(outcomes)
}

async fn persist_challenge(
    conn: &mut diesel_async::AsyncPgConnection,
    record: &OrganizationRegistrationChallengeRecord,
) -> PersistenceResult<()> {
    let value = serde_json::to_value(record)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    let changed = sql_query(
        "UPDATE organization_registration_challenges SET \
            record = $2, consumed_request_digest = $3, consumed_outcome_id = $4, consumed_at = $5 \
         WHERE challenge_id = $1",
    )
    .bind::<Text, _>(&record.challenge.challenge_id)
    .bind::<Jsonb, _>(&value)
    .bind::<diesel::sql_types::Nullable<Text>, _>(
        record
            .consumed_request_digest
            .as_ref()
            .map(|digest| digest.as_str()),
    )
    .bind::<diesel::sql_types::Nullable<Text>, _>(record.consumed_outcome_id.as_deref())
    .bind::<diesel::sql_types::Nullable<Timestamptz>, _>(record.consumed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(PersistenceError::Internal(
            "organization registration challenge disappeared during commit".to_owned(),
        ));
    }
    Ok(())
}

async fn persist_state(
    conn: &mut diesel_async::AsyncPgConnection,
    state: &OrganizationRegistrationStateRecord,
) -> PersistenceResult<()> {
    state.validate()?;
    let value = serde_json::to_value(state)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    let current = state.current()?;
    let current_generation = i64::try_from(state.current_generation).map_err(|_| {
        PersistenceError::Conflict("organization registration generation overflow".to_owned())
    })?;
    sql_query(
        "INSERT INTO organization_registration_states \
            (organization_id, current_generation, current_outcome_id, state, updated_at) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (organization_id) DO UPDATE SET \
            current_generation = EXCLUDED.current_generation, \
            current_outcome_id = EXCLUDED.current_outcome_id, \
            state = EXCLUDED.state, \
            updated_at = EXCLUDED.updated_at",
    )
    .bind::<Text, _>(&state.organization_id)
    .bind::<BigInt, _>(current_generation)
    .bind::<Text, _>(&current.current_outcome_id)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(current.updated_at)
    .execute(conn)
    .await
    .map(|_| ())
    .map_err(PersistenceError::database)
}

async fn persist_outcomes(
    conn: &mut diesel_async::AsyncPgConnection,
    outcomes: &BTreeMap<String, OrganizationRegistrationOutcome>,
    committed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    for (outcome_id, outcome) in outcomes {
        let value = serde_json::to_value(outcome)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let generation = i64::try_from(outcome.registration_receipt.registration_generation)
            .map_err(|_| {
                PersistenceError::Conflict(
                    "organization registration generation overflow".to_owned(),
                )
            })?;
        sql_query(
            "INSERT INTO organization_registration_outcomes \
                (outcome_id, organization_id, registration_generation, outcome, committed_at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (outcome_id) DO NOTHING",
        )
        .bind::<Text, _>(outcome_id)
        .bind::<Text, _>(&outcome.registration_receipt.organization_id)
        .bind::<BigInt, _>(generation)
        .bind::<Jsonb, _>(&value)
        .bind::<Timestamptz, _>(committed_at)
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
        let stored = load_outcome(conn, outcome_id).await?.ok_or_else(|| {
            PersistenceError::Internal(
                "organization registration outcome insert disappeared".to_owned(),
            )
        })?;
        if &stored != outcome {
            return Err(PersistenceError::Conflict(
                "organization registration outcome is immutable".to_owned(),
            ));
        }
    }
    Ok(())
}

fn challenge_not_found() -> PersistenceError {
    PersistenceError::Conflict(
        "organization_registration_challenge_invalid: challenge not found".to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::{
        OrganizationRegistrationChallenge, OrganizationRegistrationScope,
    };
    use arkret_wire::{Did, DidCoreId, ProofContextId, TrustDomainId, WebOrigin};
    use chrono::{Duration, TimeZone, Utc};

    use super::{ChallengeRow, OrganizationRegistrationChallengeRecord, PersistenceError};

    #[test]
    fn challenge_row_rejects_embedded_did_and_stable_id_mismatch() {
        let created_at = Utc
            .with_ymd_and_hms(2026, 8, 29, 0, 0, 0)
            .single()
            .expect("valid fixture timestamp");
        let organization_id = DidCoreId::new("ak:did_core:webvh:zDifferentOrganization").unwrap();
        let challenge = OrganizationRegistrationChallenge {
            challenge_id: format!("ak:organization_registration_challenge:{}", "a".repeat(64)),
            organization_id: organization_id.clone(),
            organization_did: Did::new("did:webvh:zActualOrganization:organization.example")
                .unwrap(),
            purpose: ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1.to_owned(),
            nonce: "fixture_challenge_nonce_000001".to_owned(),
            audience_id: DidCoreId::new("ak:did_core:webvh:zService").unwrap(),
            origin: WebOrigin::new("https://service.example").unwrap(),
            trust_domain: TrustDomainId::new("ak:trust_domain:service.example").unwrap(),
            local_admin_subject_id: DidCoreId::new("ak:did_core:webvh:zAdmin").unwrap(),
            requested_scopes: vec![OrganizationRegistrationScope::OrganizationProfileManage],
            expires_at: created_at + Duration::seconds(300),
            created_at,
        };
        let record = OrganizationRegistrationChallengeRecord::prepared(challenge);
        let row = ChallengeRow {
            challenge_id: record.challenge.challenge_id.clone(),
            organization_id,
            record: serde_json::to_value(&record).unwrap(),
            consumed_request_digest: None,
            consumed_outcome_id: None,
            consumed_at: None,
        };

        let error = OrganizationRegistrationChallengeRecord::try_from(row).unwrap_err();
        assert!(matches!(error, PersistenceError::SchemaViolation(_)));
    }
}
