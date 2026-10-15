use arkret_wire::OpaqueLocalId;
use coland_storage::PendingAgentPairingCommitIntent;
use diesel::dsl::case_when;
use diesel::{
    BoolExpressionMethods, ExpressionMethods, PgExpressionMethods, QueryDsl, SelectableHelper,
};
use diesel_async::AsyncConnection;

use super::{
    AgentPairingCommitIntent, AgentParticipationStore, AgentPrincipalRecord, AgentPrincipalRow,
    AgentRuntimeActivation, AgentRuntimeApprovalWrite, AgentRuntimeEnqueueOutcome,
    AgentRuntimeMessageRecord, AgentStore, BigInt, Bool, EnqueueAgentRuntimeMessage, Jsonb,
    Nullable, OptionalExtension, PersistenceError, PersistenceResult, PgPool, PgTransactionError,
    QueryableByName, RunQueryDsl, Text, Timestamptz, Utc, Uuid, Value, async_trait, ids,
    pack_runtime_key_material, pg_conn, sql_query, sql_types,
};
use crate::schema::agent_principals;

#[derive(QueryableByName)]
struct AgentRuntimeMessageRow {
    #[diesel(sql_type = sql_types::Uuid)]
    message_id: Uuid,
    #[diesel(sql_type = Text)]
    request_key: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Text)]
    agent_id: String,
    #[diesel(sql_type = Text)]
    verification_method: String,
    #[diesel(sql_type = Text)]
    authorized_event_ref: String,
    #[diesel(sql_type = Jsonb)]
    content: Value,
    #[diesel(sql_type = Timestamptz)]
    enqueued_at: chrono::DateTime<Utc>,
}

impl From<AgentRuntimeMessageRow> for AgentRuntimeMessageRecord {
    fn from(row: AgentRuntimeMessageRow) -> Self {
        Self {
            message_id: row.message_id,
            request_key: row.request_key,
            request_digest: row.request_digest,
            agent_id: row.agent_id,
            verification_method: row.verification_method,
            authorized_event_ref: row.authorized_event_ref,
            content: row.content,
            enqueued_at: row.enqueued_at,
        }
    }
}
#[derive(QueryableByName)]
struct AgentParticipationRow {
    #[diesel(sql_type = Text)]
    agent_id: String,
    #[diesel(sql_type = Text)]
    scope_kind: String,
    #[diesel(sql_type = Text)]
    scope_key: String,
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    scope: Value,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Bool)]
    reply_message: bool,
    #[diesel(sql_type = Bool)]
    reaction_add: bool,
    #[diesel(sql_type = Bool)]
    reaction_remove: bool,
    #[diesel(sql_type = Bool)]
    accept_third_party_mention: bool,
    #[diesel(sql_type = Bool)]
    act_on_behalf: bool,
}
impl From<AgentParticipationRow> for Value {
    fn from(row: AgentParticipationRow) -> Self {
        serde_json::json!({
            "agent_id": row.agent_id,
            "scope_kind": row.scope_kind,
            "scope_key": row.scope_key,
            "realm_id": row.realm_id,
            "scope": row.scope,
            "version": row.version,
            "reply_message": row.reply_message,
            "reaction_add": row.reaction_add,
            "reaction_remove": row.reaction_remove,
            "accept_third_party_mention": row.accept_third_party_mention,
            "act_on_behalf": row.act_on_behalf,
        })
    }
}
#[derive(QueryableByName)]
struct ParticipationVersionRow {
    #[diesel(sql_type = BigInt)]
    version: i64,
}

pub struct PgAgentParticipationStore {
    pub pool: PgPool,
}
#[async_trait]
impl AgentParticipationStore for PgAgentParticipationStore {
    async fn compare_and_swap_selection(
        &self,
        record: Value,
        expected_version: u64,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let get_str = |key: &str| -> PersistenceResult<String> {
            record
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    PersistenceError::Internal(format!("agent participation record missing {key}"))
                })
        };
        let get_bool = |key: &str| -> PersistenceResult<bool> {
            record.get(key).and_then(Value::as_bool).ok_or_else(|| {
                PersistenceError::SchemaViolation(format!(
                    "agent participation record missing boolean {key}"
                ))
            })
        };
        let bits =
            arkret_models_collaboration::governance::agent_participation::ParticipationBits {
                reply_message: get_bool("reply_message")?,
                reaction_add: get_bool("reaction_add")?,
                reaction_remove: get_bool("reaction_remove")?,
                accept_third_party_mention: get_bool("accept_third_party_mention")?,
                act_on_behalf: get_bool("act_on_behalf")?,
            };
        let accepted_version = expected_version.checked_add(1).ok_or_else(|| {
            PersistenceError::Internal("agent participation version overflow".to_owned())
        })?;
        let accepted_version = i64::try_from(accepted_version).map_err(|_| {
            PersistenceError::Internal(
                "agent participation version exceeds storage range".to_owned(),
            )
        })?;
        let expected_version = i64::try_from(expected_version).map_err(|_| {
            PersistenceError::Internal(
                "agent participation version exceeds storage range".to_owned(),
            )
        })?;
        if record.get("version").and_then(Value::as_i64) != Some(accepted_version) {
            return Err(PersistenceError::Internal(
                "agent participation record has invalid next version".to_owned(),
            ));
        }
        let agent_id = get_str("agent_id")?;
        let scope_kind = get_str("scope_kind")?;
        let scope_key = get_str("scope_key")?;
        let realm_id = get_str("realm_id")?;
        let scope = record.get("scope").cloned().unwrap_or(Value::Null);
        (*conn).transaction::<bool, PgTransactionError, _>(async move |conn| {
            crate::agent_participation_admission::lock_selection(conn, &agent_id, false).await?;
            let present = sql_query("SELECT version FROM agent_participation WHERE agent_id=$1 AND scope_key=$2")
                .bind::<Text,_>(&agent_id).bind::<Text,_>(&scope_key)
                .get_result::<ParticipationVersionRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            if present.map(|row| row.version).unwrap_or(0) != expected_version { return Ok(false); }
            crate::realm_identity::ensure_realm_pk(conn, &realm_id).await?;
        sql_query(
            "INSERT INTO agent_participation \
             (id, agent_id, scope_kind, scope_key, realm_id, scope, version, reply_message, \
               reaction_add, reaction_remove, accept_third_party_mention, act_on_behalf, updated_at) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW() WHERE $13=0 OR EXISTS(SELECT 1 FROM agent_participation WHERE agent_id=$2 AND scope_key=$4 AND version=$13) \
             ON CONFLICT (agent_id, scope_key) DO UPDATE SET \
             scope_kind = EXCLUDED.scope_kind, realm_id = EXCLUDED.realm_id, \
             scope = EXCLUDED.scope, version = EXCLUDED.version, \
             reply_message = EXCLUDED.reply_message, reaction_add = EXCLUDED.reaction_add, \
             reaction_remove = EXCLUDED.reaction_remove, \
             accept_third_party_mention = EXCLUDED.accept_third_party_mention, \
             act_on_behalf = EXCLUDED.act_on_behalf, updated_at = NOW() \
             WHERE agent_participation.version = $13",
        )
        .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
        .bind::<Text, _>(&agent_id)
        .bind::<Text, _>(&scope_kind)
        .bind::<Text, _>(&scope_key)
        .bind::<Text, _>(&realm_id)
        .bind::<Jsonb, _>(&scope)
        .bind::<BigInt, _>(accepted_version)
        .bind::<Bool, _>(bits.reply_message)
        .bind::<Bool, _>(bits.reaction_add)
        .bind::<Bool, _>(bits.reaction_remove)
        .bind::<Bool, _>(bits.accept_third_party_mention)
        .bind::<Bool, _>(bits.act_on_behalf)
        .bind::<BigInt, _>(expected_version)
        .execute(&mut *conn)
        .await
        .map(|affected| affected == 1)
        .map_err(PersistenceError::database).map_err(Into::into)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn list_selections(&self, agent_id: &str) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT agent_id, scope_kind, scope_key, realm_id, scope, version, reply_message, \
             reaction_add, reaction_remove, accept_third_party_mention, act_on_behalf \
             FROM agent_participation \
             WHERE agent_id = $1 ORDER BY scope_key",
        )
        .bind::<Text, _>(agent_id)
        .load::<AgentParticipationRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn ceilings_for_scope_keys(
        &self,
        scope_keys: &[String],
    ) -> PersistenceResult<Vec<Value>> {
        if scope_keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        let mut rows = Vec::with_capacity(scope_keys.len());
        for scope in scope_keys {
            let locator = scope
                .split_once(':')
                .ok_or_else(|| {
                    PersistenceError::SchemaViolation("invalid participation scope key".into())
                })?
                .1;
            let realm = locator
                .split(":ak:circle:")
                .next()
                .unwrap_or(locator)
                .split(":ak:strand:")
                .next()
                .unwrap_or(locator);
            let component =
                crate::agent_participation_admission::governance_component(conn, realm, scope)
                    .await?;
            let mut value = serde_json::to_value(component.unwrap_or(arkret_models_collaboration::governance::agent_participation::ParticipationBits::ALL)).map_err(PersistenceError::database)?;
            value
                .as_object_mut()
                .expect("typed participation bits serialize to an object")
                .insert("scope_key".into(), Value::String(scope.clone()));
            rows.push(value);
        }
        Ok(rows)
        }).await.map_err(PgTransactionError::into_persistence)
    }
}
/// Exact immutable receipt retained under the caller's held authority transaction.
pub(crate) async fn pairing_scope_receipt_in_connection(
    conn: &mut diesel_async::AsyncPgConnection,
    event_id: &str,
) -> PersistenceResult<Option<coland_storage::AgentPairingReceipt>> {
    #[derive(QueryableByName)]
    struct Receipt {
        #[diesel(sql_type = Jsonb)]
        receipt: Value,
    }
    let row = sql_query("SELECT jsonb_build_object('agent_id',agent_id,'controller_principal_id',controller_principal_id,'request_digest',request_digest,'authorize_event_ref',authorize_event_ref,'pairing_request_id',pairing_request_id,'approval_request_id',approval_request_id,'runtime_key_binding_digest',runtime_key_binding_digest,'scope_custody_ref',scope_custody_ref,'outcome',jsonb_build_object('activation_state',activation_state,'authorize_event_ref',authorize_event_ref)) AS receipt FROM agent_pairing_receipts WHERE authorize_event_ref=$1 FOR SHARE")
        .bind::<Text,_>(event_id).get_result::<Receipt>(conn).await.optional().map_err(PersistenceError::database)?;
    row.map(|row| serde_json::from_value(row.receipt).map_err(PersistenceError::database))
        .transpose()
}

pub struct PgAgentStore {
    pub pool: PgPool,
}

#[async_trait]
impl AgentStore for PgAgentStore {
    async fn management_review_request(
        &self,
        caller: &arkret_wire::ActorId,
        request: &arkret_models_integration::management_review::ManagementReviewRequestBody,
        producer: Option<&coland_storage::SelfProducerCommitGuard>,
        current: &coland_storage::ManagementReviewCurrent,
        _at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<arkret_models_integration::management_review::ManagementReviewOutcome>
    {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(crate::agent_management_review::request_in_connection(
                conn, caller, request, producer, current,
            )
            .await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn management_review_status(
        &self,
        caller: &arkret_wire::ActorId,
        request: &arkret_models_integration::management_review::ManagementReviewLookupRequestBody,
        current: &coland_storage::ManagementReviewCurrent,
        _at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<arkret_models_integration::management_review::ManagementReviewOutcome>
    {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(crate::agent_management_review::status_in_connection(
                conn,
                caller,
                &request.request_id,
                current,
            )
            .await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn management_review_material(
        &self,
        caller: &arkret_wire::ActorId,
        id: &str,
        new_signatures: &[arkret_wire::ApprovalSignature],
    ) -> PersistenceResult<coland_storage::ManagementReviewMaterial> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(crate::agent_management_review::material_in_connection(
                conn,
                caller,
                id,
                new_signatures,
            )
            .await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn management_review_decide(
        &self,
        caller: &arkret_wire::ActorId,
        request: &arkret_models_integration::management_review::ManagementReviewDecisionRequestBody,
        methods: &[coland_storage::ApprovalHistoricalMethod],
        current: &coland_storage::ManagementReviewCurrent,
        _at: chrono::DateTime<Utc>,
    ) -> PersistenceResult<arkret_models_integration::management_review::ManagementReviewOutcome>
    {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(crate::agent_management_review::decide_in_connection(
                conn, caller, request, methods, current,
            )
            .await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn pairing_receipt(
        &self,
        event_id: &str,
    ) -> PersistenceResult<Option<coland_storage::AgentPairingReceipt>> {
        #[derive(QueryableByName)]
        struct Receipt {
            #[diesel(sql_type = Text)]
            agent_id: String,
            #[diesel(sql_type = Text)]
            controller_principal_id: String,
            #[diesel(sql_type = Text)]
            request_digest: String,
            #[diesel(sql_type = Text)]
            authorize_event_ref: String,
            #[diesel(sql_type = Text)]
            activation_state: String,
            #[diesel(sql_type = Text)]
            pairing_request_id: String,
            #[diesel(sql_type = Text)]
            approval_request_id: String,
            #[diesel(sql_type = Text)]
            runtime_key_binding_digest: String,
            #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
            scope_custody_ref: Option<Value>,
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query("UPDATE agent_pairing_receipts SET activation_state = 'cancelled' WHERE authorize_event_ref = $1 AND activation_state = 'awaiting_source_commit' AND expires_at <= NOW()")
            .bind::<Text,_>(event_id).execute(&mut *conn).await.map_err(PersistenceError::database)?;
        let row = sql_query("SELECT agent_id, controller_principal_id, request_digest, authorize_event_ref, activation_state, scope_custody_ref, pairing_request_id, approval_request_id, runtime_key_binding_digest FROM agent_pairing_receipts WHERE authorize_event_ref = $1")
            .bind::<Text,_>(event_id).get_result::<Receipt>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        row.map(|row| {
            let activation_state = match row.activation_state.as_str() {
                "awaiting_source_commit" => arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::AwaitingSourceCommit,
                "active" => arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::Active,
                "cancelled" => arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::Cancelled,
                value => return Err(PersistenceError::Internal(format!("invalid Agent pairing receipt activation state: {value}"))),
            };
            let authorize_event_ref = arkret_wire::EventId::new(row.authorize_event_ref)
                .map_err(|error| PersistenceError::Internal(format!("invalid Agent pairing receipt Event id: {error}")))?;
            Ok(coland_storage::AgentPairingReceipt {
                agent_id: row.agent_id,
                controller_principal_id: row.controller_principal_id,
                scope_custody_ref: row.scope_custody_ref.map(serde_json::from_value).transpose().map_err(PersistenceError::database)?,
                request_digest: row.request_digest,
                authorize_event_ref: authorize_event_ref.to_string(),
                pairing_request_id: OpaqueLocalId::new(row.pairing_request_id).map_err(PersistenceError::database)?,
                approval_request_id: OpaqueLocalId::new(row.approval_request_id).map_err(PersistenceError::database)?,
                runtime_key_binding_digest: row.runtime_key_binding_digest,
                outcome: arkret_models_collaboration::agent_operations::AgentKeyPairOutcome {
                    activation_state,
                    authorize_event_ref,
                },
            })
        })
        .transpose()
    }

    async fn qualified_scope_receipt_for_pairing(
        &self,
        agent_id: &str,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<coland_storage::AgentPairingReceipt>> {
        #[derive(QueryableByName)]
        struct Source {
            #[diesel(sql_type = Text)]
            authorize_event_ref: String,
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = sql_query("SELECT authorize_event_ref FROM agent_pairing_receipts WHERE agent_id=$1 AND pairing_request_id=$2 AND activation_state='active' LIMIT 2")
            .bind::<Text,_>(agent_id).bind::<Text,_>(pairing_request_id).load::<Source>(&mut *conn).await.map_err(PersistenceError::database)?;
        if rows.len() > 1 {
            return Err(PersistenceError::SchemaViolation(
                "ambiguous qualified Agent pairing receipt".into(),
            ));
        }
        drop(conn);
        if let Some(row) = rows.as_slice().first() {
            self.pairing_receipt(&row.authorize_event_ref).await
        } else {
            Ok(None)
        }
    }

    async fn pending_pairings_after(
        &self,
        after_id: &str,
        limit: usize,
    ) -> PersistenceResult<Vec<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let rows = agent_principals::table
            .filter(agent_principals::id.gt(after_id))
            .filter(agent_principals::approval_request_id.is_not_null())
            .order(agent_principals::id.asc())
            .limit(limit.min(128) as i64)
            .select(AgentPrincipalRow::as_select())
            .load::<AgentPrincipalRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn put(&self, principal: AgentPrincipalRecord) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let principal = AgentPrincipalRow::try_from(principal)?;
        let agent_id = principal.id.clone();
        let upsert = diesel::insert_into(agent_principals::table)
            .values(&principal)
            .on_conflict(agent_principals::id)
            .do_update()
            .set(&principal);
        let affected = diesel::query_dsl::methods::FilterDsl::filter(
            upsert,
            agent_principals::controller_principal_id
                .eq(&principal.controller_principal_id)
                .and(
                    agent_principals::principal_control_realm_id
                        .eq(&principal.principal_control_realm_id),
                )
                .and(
                    agent_principals::controller_authorization_ref
                        .eq(&principal.controller_authorization_ref),
                ),
        )
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if affected == 1 {
            Ok(())
        } else {
            Err(PersistenceError::Conflict(format!(
                "Agent `{agent_id}` controller/PCR authorization binding is immutable"
            )))
        }
    }

    async fn get(&self, agent_id: &str) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let record = agent_principals::table
            .find(agent_id)
            .select(AgentPrincipalRow::as_select())
            .first::<AgentPrincipalRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
        record.map(TryInto::try_into).transpose()
    }

    async fn get_by_pairing_request_id(
        &self,
        pairing_request_id: &str,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let record = agent_principals::table
            .filter(agent_principals::pairing_request_id.eq(pairing_request_id))
            .select(AgentPrincipalRow::as_select())
            .first::<AgentPrincipalRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
        record.map(TryInto::try_into).transpose()
    }

    async fn list_for_controller(
        &self,
        controller_principal_id: &str,
    ) -> PersistenceResult<Vec<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let records = agent_principals::table
            .filter(agent_principals::controller_principal_id.eq(controller_principal_id))
            .order(agent_principals::created_at.asc())
            .select(AgentPrincipalRow::as_select())
            .load::<AgentPrincipalRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        records.into_iter().map(TryInto::try_into).collect()
    }

    async fn set_state(
        &self,
        agent_id: &str,
        state: arkret_models_collaboration::agent_operations::AgentLifecycleState,
        changed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let state = serde_json::to_value(state)
            .map_err(PersistenceError::database)?
            .as_str()
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "Agent lifecycle state is not serialized as text".to_owned(),
                )
            })?
            .to_owned();
        let updated = diesel::update(agent_principals::table.find(agent_id))
            .set((
                agent_principals::state.eq(state),
                agent_principals::state_changed_at.eq(changed_at),
                agent_principals::updated_at.eq(changed_at),
            ))
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        Ok(updated > 0)
    }

    async fn activate_runtime_if_current(
        &self,
        activation: &AgentRuntimeActivation,
    ) -> PersistenceResult<bool> {
        if activation.scope_custody_ref.is_none() {
            return Err(PersistenceError::SchemaViolation(
                "Agent activation lacks verifier-private scope custody".into(),
            ));
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let authorized_key_event = (activation.status
            == arkret_models_collaboration::agent_operations::AgentLifecycleState::Active)
            .then(|| {
                crate::agent_principal_row::pack_authorized_key_material(
                    Some(activation.authorized_key_event.clone()),
                    activation.signer_resolution_evidence_ref.clone(),
                    activation.current_signer_evidence.clone(),
                )
            })
            .transpose()?
            .flatten();
        let pending_intent = serde_json::to_value(PendingAgentPairingCommitIntent {
            request_digest: activation.paired_request_digest.clone(),
            authorize_event_id: activation.authorized_event_ref.clone(),
            key_authorization_event: Some(activation.frozen_authorize_event.clone()),
            scope_custody_ref: activation.scope_custody_ref.clone(),
        })
        .map_err(|error| {
            PersistenceError::Internal(format!(
                "encode pending Agent pairing commit intent: {error}"
            ))
        })?;
        let key_expires_at: Option<chrono::DateTime<Utc>> = activation
            .authorized_key_event
            .payload
            .get("expires_at")
            .filter(|value| !value.is_null())
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            if activation.status
                != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
            {
                return Err(PersistenceError::SchemaViolation(
                    "Agent runtime activation requires an active authority outcome".into(),
                )
                .into());
            }
            let authorized_key_event = authorized_key_event.as_ref().ok_or_else(|| {
                PersistenceError::SchemaViolation(
                    "active Agent authorization material is absent".to_owned(),
                )
            })?;
            let rows = diesel::update(
                agent_principals::table
                    .filter(agent_principals::id.eq(&activation.agent_id))
                    .filter(agent_principals::state.eq_any(["active", "paused"]))
                    .filter(
                        agent_principals::approval_request_id
                            .eq(activation.approval_request_id.as_str()),
                    )
                    .filter(
                        agent_principals::runtime_key_binding_digest
                            .eq(&activation.runtime_key_binding_digest),
                    )
                    .filter(
                        agent_principals::pairing_request_id
                            .eq(activation.pairing_request_id.as_str()),
                    )
                    .filter(agent_principals::pending_pairing_commit_intent.eq(&pending_intent))
                    .filter(agent_principals::pairing_expires_at.gt(diesel::dsl::sql::<
                        Nullable<Timestamptz>,
                    >(
                        "clock_timestamp()"
                    )))
                    .filter(
                        diesel::dsl::sql::<Bool>("(")
                            .bind::<Nullable<Timestamptz>, _>(key_expires_at)
                            .sql(" IS NULL OR clock_timestamp() < ")
                            .bind::<Nullable<Timestamptz>, _>(key_expires_at)
                            .sql(")"),
                    ),
            )
            .set((
                // Runtime key activation records the authorization; it is not a
                // lifecycle transition, so the lifecycle `state` is left untouched
                // (key-management.md §3.6.1). runtime_state derives to ready.
                agent_principals::updated_at.eq(activation.authorized_at),
                agent_principals::authorized_event_ref.eq(&activation.authorized_event_ref),
                agent_principals::authorized_verification_method
                    .eq(&activation.authorized_verification_method),
                agent_principals::authorized_public_key_digest
                    .eq(&activation.authorized_public_key_digest),
                agent_principals::authorized_key_event.eq(authorized_key_event),
                agent_principals::paired_pairing_request_id
                    .eq(activation.pairing_request_id.as_str()),
                agent_principals::paired_request_digest.eq(&activation.paired_request_digest),
                agent_principals::pending_pairing_commit_intent.eq(None::<Value>),
                agent_principals::approval_requested_at.eq(None::<chrono::DateTime<chrono::Utc>>),
                agent_principals::runtime_key_binding_digest.eq(None::<String>),
                // Clears the pending request together with its public-key and
                // attestation digests; they share one column.
                agent_principals::runtime_key_material.eq(None::<Value>),
            ))
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            Ok(rows == 1)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn put_pairing_commit_intent_if_compatible(
        &self,
        intent: &AgentPairingCommitIntent,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        if intent.scope_custody_ref.is_none() {
            return Err(PersistenceError::SchemaViolation(
                "Agent pairing lacks verifier-private scope custody".into(),
            ));
        }
        let intent_value = serde_json::to_value(PendingAgentPairingCommitIntent {
            request_digest: intent.request_digest.clone(),
            authorize_event_id: intent.authorize_event_id.clone(),
            key_authorization_event: Some(intent.key_authorization_event.clone()),
            scope_custody_ref: intent.scope_custody_ref.clone(),
        })
        .map_err(|error| {
            PersistenceError::Internal(format!(
                "encode pending Agent pairing commit intent: {error}"
            ))
        })?;
        let record = diesel::update(
            agent_principals::table
                .filter(agent_principals::id.eq(&intent.agent_id))
                .filter(agent_principals::state.eq_any(["active", "paused"]))
                .filter(
                    agent_principals::approval_request_id.eq(intent.approval_request_id.as_str()),
                )
                .filter(
                    agent_principals::runtime_key_binding_digest
                        .eq(&intent.runtime_key_binding_digest),
                )
                .filter(agent_principals::pairing_request_id.eq(intent.pairing_request_id.as_str()))
                .filter(
                    agent_principals::paired_pairing_request_id
                        .is_distinct_from(intent.pairing_request_id.as_str()),
                )
                .filter(
                    agent_principals::pending_pairing_commit_intent
                        .is_null()
                        .or(agent_principals::pending_pairing_commit_intent.eq(&intent_value)),
                ),
        )
        .set((
            agent_principals::pending_pairing_commit_intent.eq(&intent_value),
            agent_principals::updated_at.eq(Utc::now()),
        ))
        .returning(AgentPrincipalRow::as_returning())
        .get_result::<AgentPrincipalRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        record.map(TryInto::try_into).transpose()
    }

    async fn clear_runtime_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        diesel::update(
            agent_principals::table
                .filter(agent_principals::id.eq(agent_id))
                .filter(agent_principals::approval_request_id.eq(approval_request_id))
                .filter(agent_principals::authorized_event_ref.is_not_null()),
        )
        .set((
            agent_principals::approval_request_id.eq(None::<String>),
            agent_principals::approval_notification_id.eq(None::<Uuid>),
            agent_principals::updated_at.eq(Utc::now()),
        ))
        .execute(&mut *conn)
        .await
        .map(|rows| rows == 1)
        .map_err(PersistenceError::database)
    }

    async fn put_runtime_approval_if_compatible(
        &self,
        write: &AgentRuntimeApprovalWrite,
    ) -> PersistenceResult<Option<AgentPrincipalRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let approval_notification_id =
            ids::typed_uuid_part_expect_internal(&write.approval_notification_id);
        let runtime_key_request =
            serde_json::to_value(&write.runtime_key_request).map_err(|error| {
                PersistenceError::Internal(format!(
                    "encode typed Agent runtime key request: {error}"
                ))
            })?;
        let runtime_key_material = pack_runtime_key_material(
            Some(runtime_key_request),
            Some(write.runtime_public_key_digest.clone()),
            Some(write.runtime_attestation_digest.clone()),
            Some(write.proof_verified_at),
        )?;
        let record = diesel::update(
            agent_principals::table
                .filter(agent_principals::id.eq(&write.agent_id))
                .filter(agent_principals::state.eq_any(["active", "paused"]))
                .filter(agent_principals::pairing_request_id.eq(write.pairing_request_id.as_str()))
                .filter(
                    agent_principals::paired_pairing_request_id
                        .is_distinct_from(write.pairing_request_id.as_str()),
                )
                .filter(
                    agent_principals::runtime_key_binding_digest
                        .is_null()
                        .or(agent_principals::runtime_key_binding_digest
                            .eq(&write.runtime_key_binding_digest)),
                ),
        )
        .set((
            agent_principals::approval_request_id.eq(case_when::<_, _, Nullable<Text>>(
                agent_principals::approval_request_id.is_null(),
                Some(write.approval_request_id.as_str()),
            )
            .otherwise(agent_principals::approval_request_id)),
            agent_principals::approval_notification_id.eq(case_when::<
                _,
                _,
                Nullable<sql_types::Uuid>,
            >(
                agent_principals::approval_notification_id.is_null(),
                Some(approval_notification_id),
            )
            .otherwise(agent_principals::approval_notification_id)),
            agent_principals::approval_requested_at.eq(case_when::<_, _, Nullable<Timestamptz>>(
                agent_principals::approval_requested_at.is_null(),
                Some(write.approval_requested_at),
            )
            .otherwise(agent_principals::approval_requested_at)),
            agent_principals::controller_account_pk.eq(write.controller_account_pk.get()),
            agent_principals::recipient_id.eq(&write.recipient_id),
            agent_principals::runtime_key_binding_digest.eq(&write.runtime_key_binding_digest),
            agent_principals::runtime_key_material.eq(runtime_key_material),
            agent_principals::updated_at.eq(Utc::now()),
        ))
        .returning(AgentPrincipalRow::as_returning())
        .get_result::<AgentPrincipalRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        record.map(TryInto::try_into).transpose()
    }

    async fn enqueue_runtime_message_if_current(
        &self,
        command: &EnqueueAgentRuntimeMessage,
    ) -> PersistenceResult<AgentRuntimeEnqueueOutcome> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let command = command.clone();
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // Exact replay is authoritative even if the runtime has since
            // rotated.  The row lock also serializes competing request-key
            // attempts before the active snapshot is inspected.
            let existing = sql_query(
                "SELECT message_id, request_key, request_digest, agent_id, \
                        verification_method, authorized_event_ref, content, enqueued_at \
                   FROM agent_runtime_messages WHERE request_key = $1 FOR UPDATE",
            )
            .bind::<Text, _>(&command.request_key)
            .get_result::<AgentRuntimeMessageRow>(conn)
            .await
            .optional()?;
            if let Some(existing) = existing {
                let existing = AgentRuntimeMessageRecord::from(existing);
                return Ok(
                    if existing.request_digest == command.request_digest
                        && existing.agent_id == command.snapshot.agent_id
                        && existing.content == command.content
                    {
                        AgentRuntimeEnqueueOutcome::Duplicate(existing)
                    } else {
                        AgentRuntimeEnqueueOutcome::RequestConflict
                    },
                );
            }

            let agent = agent_principals::table
                .find(&command.snapshot.agent_id)
                .for_update()
                .select(AgentPrincipalRow::as_select())
                .first::<AgentPrincipalRow>(conn)
                .await
                .optional()?;
            let Some(agent) = agent else {
                return Ok(AgentRuntimeEnqueueOutcome::SnapshotConflict);
            };
            let agent: AgentPrincipalRecord = agent.try_into()?;
            if agent.state
                != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
                || agent.authorized_verification_method.as_deref()
                    != Some(command.snapshot.verification_method.as_str())
                || agent.authorized_event_ref.as_deref()
                    != Some(command.snapshot.authorized_event_ref.as_str())
                || agent.updated_at != command.snapshot.updated_at
                || agent.authorized_key_event.is_none()
            {
                return Ok(AgentRuntimeEnqueueOutcome::SnapshotConflict);
            }

            let message_id = Uuid::now_v7();
            let stored = sql_query(
                "INSERT INTO agent_runtime_messages \
                    (message_id, request_key, request_digest, agent_id, verification_method, \
                     authorized_event_ref, content, enqueued_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 RETURNING message_id, request_key, request_digest, agent_id, \
                           verification_method, authorized_event_ref, content, enqueued_at",
            )
            .bind::<sql_types::Uuid, _>(message_id)
            .bind::<Text, _>(&command.request_key)
            .bind::<Text, _>(&command.request_digest)
            .bind::<Text, _>(&command.snapshot.agent_id)
            .bind::<Text, _>(&command.snapshot.verification_method)
            .bind::<Text, _>(&command.snapshot.authorized_event_ref)
            .bind::<Jsonb, _>(&command.content)
            .bind::<Timestamptz, _>(command.enqueued_at)
            .get_result::<AgentRuntimeMessageRow>(conn)
            .await?;
            Ok(AgentRuntimeEnqueueOutcome::Stored(stored.into()))
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}
