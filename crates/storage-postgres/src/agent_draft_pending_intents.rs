use coland_storage::{
    AgentDraftPendingIntentCommit, AgentDraftPendingIntentConsumption,
    AgentDraftPendingIntentRecord, AgentDraftPendingIntentState, AgentDraftPendingIntentStore,
    PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Binary, Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::{PgPool, pg_conn};

#[derive(Clone)]
pub struct PgAgentDraftPendingIntentStore {
    pub(crate) pool: PgPool,
}

impl PgAgentDraftPendingIntentStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(diesel::QueryableByName)]
struct PendingIntentRow {
    #[diesel(sql_type = Jsonb)]
    controller_account_id: serde_json::Value,
    #[diesel(sql_type = Text)]
    agent_id: String,
    #[diesel(sql_type = Text)]
    draft_id: String,
    #[diesel(sql_type = Text)]
    proposed_action: String,
    #[diesel(sql_type = Jsonb)]
    target: serde_json::Value,
    #[diesel(sql_type = Text)]
    content_digest: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    content_handoff: Option<serde_json::Value>,
    #[diesel(sql_type = Text)]
    canonical_event_digest: String,
    #[diesel(sql_type = Text)]
    accepted_event_id: String,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Text)]
    state: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    consumption: Option<serde_json::Value>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    expired_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(diesel::QueryableByName)]
struct AcceptedDraftSource {
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
}

impl TryFrom<PendingIntentRow> for AgentDraftPendingIntentRecord {
    type Error = PersistenceError;

    fn try_from(row: PendingIntentRow) -> Result<Self, Self::Error> {
        let state = match row.state.as_str() {
            "available" => AgentDraftPendingIntentState::Available,
            "consumed" => AgentDraftPendingIntentState::Consumed,
            "expired" => AgentDraftPendingIntentState::Expired,
            value => {
                return Err(PersistenceError::Internal(format!(
                    "invalid agent draft pending intent state {value}"
                )));
            }
        };
        let consumption = row
            .consumption
            .map(serde_json::from_value::<PendingIntentConsumptionWire>)
            .transpose()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?
            .map(AgentDraftPendingIntentConsumption::try_from)
            .transpose()?;
        let record = Self {
            controller_account_id: serde_json::from_value(row.controller_account_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            agent_id: arkret_wire::DidCoreId::new(row.agent_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            draft_id: row.draft_id,
            proposed_action: row.proposed_action,
            target: row.target,
            content_digest: arkret_wire::Hash::new(row.content_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            content_handoff: row.content_handoff,
            canonical_event_digest: arkret_wire::Hash::new(row.canonical_event_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            accepted_event_id: arkret_wire::EventId::new(row.accepted_event_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            expires_at: row.expires_at,
            created_at: row.created_at,
            state,
            consumption,
            expired_at: row.expired_at,
        };
        let valid_shape = match record.state {
            AgentDraftPendingIntentState::Available => {
                record.content_handoff.is_some()
                    && record.consumption.is_none()
                    && record.expired_at.is_none()
            }
            AgentDraftPendingIntentState::Consumed => {
                record.content_handoff.is_none()
                    && record.consumption.is_some()
                    && record.expired_at.is_none()
            }
            AgentDraftPendingIntentState::Expired => {
                record.content_handoff.is_none()
                    && record.consumption.is_none()
                    && record.expired_at.is_some()
            }
        };
        if !valid_shape {
            return Err(PersistenceError::Internal(
                "invalid live or terminal-redacted agent draft pending intent".to_owned(),
            ));
        }
        Ok(record)
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingIntentConsumptionWire {
    account_data_set_event_id: String,
    account_data_key: String,
    accepted_revision: u64,
    consumed_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<PendingIntentConsumptionWire> for AgentDraftPendingIntentConsumption {
    type Error = PersistenceError;

    fn try_from(value: PendingIntentConsumptionWire) -> Result<Self, Self::Error> {
        Ok(Self {
            account_data_set_event_id: arkret_wire::EventId::new(value.account_data_set_event_id)
                .map_err(|error| {
                PersistenceError::Internal(error.to_string())
            })?,
            account_data_key: value.account_data_key,
            accepted_revision: value.accepted_revision,
            consumed_at: value.consumed_at,
        })
    }
}

const SELECT_COLUMNS: &str = "controller_account_id, agent_id, draft_id, proposed_action, target, \
    content_digest, content_handoff, canonical_event_digest, accepted_event_id, expires_at, \
    created_at, state, consumption, expired_at";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AgentDraftConsumptionLock {
    Available,
    ExactReplay,
}

/// Lock and validate the Station-private source row selected by an initial
/// holder-authored Agent draft Account Data create.
///
/// The digest components in `account_data_key` are intentionally opaque. The
/// only accepted binding recomputes them from the exact source-row literals by
/// calling the public SDK helper. The row lock remains held by the surrounding
/// Event transaction until both the Account Data CAS and the terminal
/// transition commit or roll back together.
pub(crate) async fn lock_agent_draft_consumption_source(
    conn: &mut AsyncPgConnection,
    controller_account_id: &arkret_wire::AccountId,
    source_pending_event_id: &arkret_wire::EventId,
    consuming_event_id: &arkret_wire::EventId,
    account_data_key: &str,
    accepted_revision: u64,
    protocol_time: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<AgentDraftConsumptionLock> {
    if accepted_revision != 1 {
        return Err(PersistenceError::SchemaViolation(
            "initial Agent draft consumption must create Account Data revision 1".to_owned(),
        ));
    }
    let controller_key = controller_account_id.to_string();
    let row = sql_query(format!(
        "SELECT {SELECT_COLUMNS} FROM agent_draft_pending_intents pending \
         WHERE controller_account_key=$1 AND accepted_event_id=$2 \
           AND EXISTS (SELECT 1 FROM actor_private_events source \
                       WHERE source.id=$3 AND source.kind='ak.agent.draft.propose') \
         FOR UPDATE OF pending"
    ))
    .bind::<Text, _>(&controller_key)
    .bind::<Text, _>(source_pending_event_id.as_str())
    .bind::<Binary, _>(source_pending_event_id.token_bytes().to_vec())
    .get_result::<PendingIntentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| {
        PersistenceError::Conflict(
            "failed_precondition: Agent draft pending source is unavailable for this controller"
                .to_owned(),
        )
    })?;
    let record = AgentDraftPendingIntentRecord::try_from(row)?;
    if record.controller_account_id != *controller_account_id {
        return Err(PersistenceError::Conflict(
            "failed_precondition: Agent draft pending source owner binding is inconsistent"
                .to_owned(),
        ));
    }
    let source = sql_query(
        "SELECT envelope FROM actor_private_events WHERE id=$1 AND kind='ak.agent.draft.propose'",
    )
    .bind::<Binary, _>(source_pending_event_id.token_bytes().to_vec())
    .get_result::<AcceptedDraftSource>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let source: arkret_wire::Event = serde_json::from_value(source.envelope).map_err(|_| {
        PersistenceError::Conflict(
            "failed_precondition: invalid accepted private draft source".into(),
        )
    })?;
    let proposed: arkret_models_collaboration::events_payloads::agent::AgentDraftProposePayload =
        serde_json::from_value(serde_json::json!(&source.payload)).map_err(|_| {
            PersistenceError::Conflict(
                "failed_precondition: invalid accepted private draft payload".into(),
            )
        })?;
    let agent_actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        record.agent_id.clone(),
        controller_account_id.station_id.clone(),
    ));
    if source.actor_id != agent_actor
        || source.executed_by.is_some()
        || source.event_id != record.accepted_event_id
        || arkret_canonical::canonical_sha256(&source).map_err(PersistenceError::database)?
            != record.canonical_event_digest.as_str()
        || proposed.controller_account_id != record.controller_account_id
        || proposed.agent_id != record.agent_id
        || proposed.draft_id != record.draft_id
        || proposed.proposed_action != record.proposed_action
        || serde_json::json!(proposed.target) != record.target
        || proposed.content_digest != record.content_digest
        || proposed.created_at != record.created_at
        || proposed.expires_at != record.expires_at
    {
        return Err(PersistenceError::Conflict(
            "failed_precondition: accepted private draft source binding is inconsistent".into(),
        ));
    }
    arkret_models_collaboration::events_payloads::account_data::validate_agent_draft_account_data_key_source(
        account_data_key,
        &record.agent_id,
        &record.draft_id,
    )
    .map_err(|error| {
        PersistenceError::Conflict(format!(
            "failed_precondition: Agent draft Account Data key does not bind its pending source: {error}"
        ))
    })?;

    match record.state {
        AgentDraftPendingIntentState::Available => {
            if protocol_time >= record.expires_at {
                return Err(PersistenceError::Conflict(
                    "failed_precondition: Agent draft pending source has expired".to_owned(),
                ));
            }
            Ok(AgentDraftConsumptionLock::Available)
        }
        AgentDraftPendingIntentState::Consumed => {
            let exact = record.consumption.as_ref().is_some_and(|consumption| {
                consumption.account_data_set_event_id == *consuming_event_id
                    && consumption.account_data_key == account_data_key
                    && consumption.accepted_revision == accepted_revision
            });
            if exact {
                Ok(AgentDraftConsumptionLock::ExactReplay)
            } else {
                Err(PersistenceError::Conflict(
                    "duplicate_conflict: Agent draft pending source was consumed by another Event"
                        .to_owned(),
                ))
            }
        }
        AgentDraftPendingIntentState::Expired => Err(PersistenceError::Conflict(
            "failed_precondition: Agent draft pending source has expired".to_owned(),
        )),
    }
}

/// Complete an already locked available source row. The guarded update is a
/// second line of defence against accidental use outside the Event unit of
/// work; zero affected rows aborts the whole transaction.
pub(crate) async fn mark_agent_draft_consumed(
    conn: &mut AsyncPgConnection,
    controller_account_id: &arkret_wire::AccountId,
    source_pending_event_id: &arkret_wire::EventId,
    consuming_event_id: &arkret_wire::EventId,
    account_data_key: &str,
    accepted_revision: u64,
    consumed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let consumption = serde_json::json!({
        "account_data_set_event_id": consuming_event_id,
        "account_data_key": account_data_key,
        "accepted_revision": accepted_revision,
        "consumed_at": arkret_canonical::format_timestamp_canonical(consumed_at),
    });
    let affected = sql_query(
        "UPDATE agent_draft_pending_intents \
         SET state='consumed', content_handoff=NULL, consumption=$3 \
         WHERE controller_account_key=$1 AND accepted_event_id=$2 \
           AND state='available' AND expires_at > $4",
    )
    .bind::<Text, _>(controller_account_id.to_string())
    .bind::<Text, _>(source_pending_event_id.as_str())
    .bind::<Jsonb, _>(consumption)
    .bind::<Timestamptz, _>(consumed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if affected != 1 {
        return Err(PersistenceError::Conflict(
            "failed_precondition: Agent draft pending source changed before consumption".to_owned(),
        ));
    }
    Ok(())
}

async fn expire_available(
    conn: &mut AsyncPgConnection,
    controller_key: &str,
    protocol_time: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    sql_query(
        "UPDATE agent_draft_pending_intents \
         SET state='expired', expired_at=expires_at, content_handoff=NULL \
         WHERE controller_account_key=$1 AND state='available' AND expires_at <= $2",
    )
    .bind::<Text, _>(controller_key)
    .bind::<Timestamptz, _>(protocol_time)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) async fn commit_agent_draft_pending_intent_in_connection(
    conn: &mut AsyncPgConnection,
    commit: &AgentDraftPendingIntentCommit,
) -> PersistenceResult<()> {
    let record = &commit.record;
    if record.state != AgentDraftPendingIntentState::Available
        || record.content_handoff.is_none()
        || record.consumption.is_some()
        || record.expired_at.is_some()
        || record.expires_at <= record.created_at
    {
        return Err(PersistenceError::SchemaViolation(
            "new agent draft pending intent must be available and unexpired".to_owned(),
        ));
    }
    let controller_json = serde_json::to_value(&record.controller_account_id)
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    let controller_key = record.controller_account_id.to_string();
    let inserted = sql_query(
        "INSERT INTO agent_draft_pending_intents \
         (controller_account_id, controller_account_key, agent_id, draft_id, proposed_action, \
          target, content_digest, content_handoff, canonical_event_digest, accepted_event_id, \
          expires_at, created_at, state) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'available') \
         ON CONFLICT DO NOTHING",
    )
    .bind::<Jsonb, _>(controller_json)
    .bind::<Text, _>(&controller_key)
    .bind::<Text, _>(record.agent_id.as_str())
    .bind::<Text, _>(&record.draft_id)
    .bind::<Text, _>(&record.proposed_action)
    .bind::<Jsonb, _>(&record.target)
    .bind::<Text, _>(record.content_digest.as_str())
    .bind::<Jsonb, _>(
        record
            .content_handoff
            .as_ref()
            .expect("validated live handoff"),
    )
    .bind::<Text, _>(record.canonical_event_digest.as_str())
    .bind::<Text, _>(record.accepted_event_id.as_str())
    .bind::<Timestamptz, _>(record.expires_at)
    .bind::<Timestamptz, _>(record.created_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted == 1 {
        return Ok(());
    }

    let existing = sql_query(format!(
        "SELECT {SELECT_COLUMNS} FROM agent_draft_pending_intents \
         WHERE controller_account_key=$1 AND agent_id=$2 AND draft_id=$3 FOR UPDATE"
    ))
    .bind::<Text, _>(&controller_key)
    .bind::<Text, _>(record.agent_id.as_str())
    .bind::<Text, _>(&record.draft_id)
    .get_result::<PendingIntentRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if existing.is_some_and(|existing| {
        existing.accepted_event_id == record.accepted_event_id.as_str()
            && existing.canonical_event_digest == record.canonical_event_digest.as_str()
    }) {
        return Ok(());
    }
    Err(PersistenceError::Conflict(
        "duplicate_conflict: agent draft pending-intent key is already occupied".to_owned(),
    ))
}

#[async_trait::async_trait]
impl AgentDraftPendingIntentStore for PgAgentDraftPendingIntentStore {
    async fn get_by_source_event(
        &self,
        controller_account_id: &arkret_wire::AccountId,
        source_event_id: &arkret_wire::EventId,
        protocol_time: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<AgentDraftPendingIntentRecord>> {
        let controller_key = controller_account_id.to_string();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        expire_available(&mut conn, &controller_key, protocol_time).await?;
        sql_query(format!(
            "SELECT {SELECT_COLUMNS} FROM agent_draft_pending_intents \
             WHERE controller_account_key=$1 AND accepted_event_id=$2"
        ))
        .bind::<Text, _>(&controller_key)
        .bind::<Text, _>(source_event_id.as_str())
        .get_result::<PendingIntentRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(AgentDraftPendingIntentRecord::try_from)
        .transpose()
    }

    async fn list_for_controller(
        &self,
        controller_account_id: &arkret_wire::AccountId,
        protocol_time: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Vec<AgentDraftPendingIntentRecord>> {
        let controller_key = controller_account_id.to_string();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        expire_available(&mut conn, &controller_key, protocol_time).await?;
        sql_query(format!(
            "SELECT {SELECT_COLUMNS} FROM agent_draft_pending_intents \
             WHERE controller_account_key=$1 ORDER BY created_at, agent_id, draft_id"
        ))
        .bind::<Text, _>(&controller_key)
        .load::<PendingIntentRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(AgentDraftPendingIntentRecord::try_from)
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use coland_storage::SyncCursorStore;
    use diesel::sql_types::BigInt;
    use diesel_async::RunQueryDsl;

    use super::*;

    fn hash(byte: char) -> arkret_wire::Hash {
        arkret_wire::Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn event_id(byte: char) -> arkret_wire::EventId {
        arkret_wire::EventId::from_event_digest(&hash(byte)).unwrap()
    }

    fn account(name: &str) -> arkret_wire::AccountId {
        arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn pending(now: chrono::DateTime<chrono::Utc>) -> AgentDraftPendingIntentCommit {
        AgentDraftPendingIntentCommit {
            record: AgentDraftPendingIntentRecord {
                controller_account_id: account("controller"),
                agent_id: arkret_wire::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
                draft_id: "draft-1".to_owned(),
                proposed_action: "compose".to_owned(),
                target: serde_json::json!({"kind":"account_data","account_data_key":"opaque"}),
                content_digest: hash('1'),
                content_handoff: Some(serde_json::json!({
                    "scheme":"ak.hpke_x25519_aead_chacha20poly1305.v1",
                    "recipients":[{
                        "recipient_device_id":"ak:device:01964137-0000-7000-8000-000000000001",
                        "recipient_hpke_key_digest":hash('2'),
                        "enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "ciphertext":"AAAAAAAAAAAAAAAAAAAAAA",
                        "ciphertext_digest":hash('3')
                    }]
                })),
                canonical_event_digest: hash('4'),
                accepted_event_id: event_id('4'),
                expires_at: now + chrono::TimeDelta::minutes(5),
                created_at: now,
                state: AgentDraftPendingIntentState::Available,
                consumption: None,
                expired_at: None,
            },
        }
    }

    #[derive(diesel::QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }

    #[tokio::test]
    async fn create_exact_replay_conflict_expiry_and_domain_isolation() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgAgentDraftPendingIntentStore { pool: pool.clone() };
        let now = "2026-09-20T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        let commit = pending(now);
        let mut conn = crate::pg_conn(&pool).await.unwrap();

        commit_agent_draft_pending_intent_in_connection(&mut conn, &commit)
            .await
            .unwrap();
        commit_agent_draft_pending_intent_in_connection(&mut conn, &commit)
            .await
            .expect("byte-identical replay returns the stored outcome");

        let sync = crate::PgSyncCursorStore { pool: pool.clone() };
        let controller_actor_key =
            arkret_wire::ActorId::account(commit.record.controller_account_id.clone())
                .canonical_key()
                .unwrap();
        let live_cut = sync.account_global_watermark().await.unwrap();
        assert_eq!(
            sync.account_global_channel_position(
                &controller_actor_key,
                "agent_draft_pending_intents",
                live_cut,
            )
            .await
            .unwrap(),
            1,
            "the frozen baseline cut uses the private channel position",
        );
        let live_page = sync
            .account_global_page(
                &controller_actor_key,
                "agent_draft_pending_intents",
                live_cut,
                "",
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(live_page.len(), 1);
        assert_eq!(live_page[0].channel_position, 1);
        assert!(!live_page[0].deleted);
        assert_eq!(
            live_page[0].payload["schema"],
            "ak.schema.agent_draft_pending_intent.v1"
        );
        assert_eq!(live_page[0].payload["state"], "available");
        assert!(live_page[0].payload.get("content_handoff").is_some());

        let rows = store
            .list_for_controller(&commit.record.controller_account_id, now)
            .await
            .unwrap();
        assert_eq!(rows, vec![commit.record.clone()]);
        assert!(
            store
                .list_for_controller(&account("foreign"), now)
                .await
                .unwrap()
                .is_empty(),
            "a different AccountId cannot read the holder handoff"
        );

        let mut conflicting = commit.clone();
        conflicting.record.canonical_event_digest = hash('5');
        assert!(matches!(
            commit_agent_draft_pending_intent_in_connection(&mut conn, &conflicting).await,
            Err(PersistenceError::Conflict(detail)) if detail.starts_with("duplicate_conflict")
        ));
        conflicting.record.accepted_event_id = event_id('5');
        assert!(matches!(
            commit_agent_draft_pending_intent_in_connection(&mut conn, &conflicting).await,
            Err(PersistenceError::Conflict(detail)) if detail.starts_with("duplicate_conflict")
        ));

        let account_rows = diesel::sql_query("SELECT count(*) AS count FROM account_datas")
            .get_result::<CountRow>(&mut conn)
            .await
            .unwrap()
            .count;
        let projection_rows = diesel::sql_query("SELECT count(*) AS count FROM projection_events")
            .get_result::<CountRow>(&mut conn)
            .await
            .unwrap()
            .count;
        assert_eq!((account_rows, projection_rows), (0, 0));

        let expired = store
            .get_by_source_event(
                &commit.record.controller_account_id,
                &commit.record.accepted_event_id,
                commit.record.expires_at,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(expired.state, AgentDraftPendingIntentState::Expired);
        assert_eq!(expired.expired_at, Some(commit.record.expires_at));
        assert!(expired.consumption.is_none());
        assert!(expired.content_handoff.is_none());

        let terminal_cut = sync.account_global_watermark().await.unwrap();
        assert_eq!(
            sync.account_global_channel_position(
                &controller_actor_key,
                "agent_draft_pending_intents",
                terminal_cut,
            )
            .await
            .unwrap(),
            2,
            "terminal redaction advances the same private channel",
        );
        let terminal_delta = sync
            .account_global_page(
                &controller_actor_key,
                "agent_draft_pending_intents",
                terminal_cut,
                "",
                Some(live_page[0].revision),
                100,
            )
            .await
            .unwrap();
        assert_eq!(terminal_delta.len(), 1);
        assert_eq!(terminal_delta[0].channel_position, 2);
        assert!(!terminal_delta[0].deleted);
        assert_eq!(terminal_delta[0].payload["state"], "expired");
        assert!(terminal_delta[0].payload.get("content_handoff").is_none());
        assert_eq!(
            terminal_delta[0].payload["expired_at"],
            serde_json::json!(arkret_canonical::format_timestamp_canonical(
                commit.record.expires_at
            ))
        );

        let deletion = diesel::sql_query(
            "DELETE FROM agent_draft_pending_intents \
             WHERE controller_account_key=$1 AND agent_id=$2 AND draft_id=$3",
        )
        .bind::<diesel::sql_types::Text, _>(commit.record.controller_account_id.to_string())
        .bind::<diesel::sql_types::Text, _>(commit.record.agent_id.as_str())
        .bind::<diesel::sql_types::Text, _>(&commit.record.draft_id)
        .execute(&mut conn)
        .await;
        assert!(
            deletion.is_err(),
            "terminal retention cannot free the create-once key before an occupied-key tombstone exists"
        );
        assert!(
            store
                .get_by_source_event(
                    &commit.record.controller_account_id,
                    &commit.record.accepted_event_id,
                    commit.record.expires_at,
                )
                .await
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            commit_agent_draft_pending_intent_in_connection(&mut conn, &conflicting).await,
            Err(PersistenceError::Conflict(detail)) if detail.starts_with("duplicate_conflict")
        ));
    }

    #[tokio::test]
    async fn transaction_rollback_leaves_no_pending_intent() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgAgentDraftPendingIntentStore { pool: pool.clone() };
        let now = "2026-09-20T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        let commit = pending(now);
        let mut conn = crate::pg_conn(&pool).await.unwrap();
        diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
        commit_agent_draft_pending_intent_in_connection(&mut conn, &commit)
            .await
            .unwrap();
        diesel::sql_query("ROLLBACK")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(
            store
                .list_for_controller(&account("controller"), now)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
