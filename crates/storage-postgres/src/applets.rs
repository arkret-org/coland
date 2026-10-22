use super::{
    AppletAuthoringPreviewRecord, AppletStore, AppletTransactionReplayBegin,
    AppletTransactionReplayRecord, AsyncConnection, ExistsRow, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl,
    Text, Timestamptz, Value, applet_registration_select_sql, applet_transaction_replay_select_sql,
    async_trait, pg_conn, sql_query,
};
#[derive(QueryableByName)]
struct AppletRegistrationRow {
    #[diesel(sql_type = Jsonb)]
    record: Value,
}
#[derive(QueryableByName)]
struct AppletTransactionReplayRow {
    #[diesel(sql_type = Text)]
    applet_id: String,
    #[diesel(sql_type = Text)]
    source_id: String,
    #[diesel(sql_type = Text)]
    idempotency_key: String,
    #[diesel(sql_type = Jsonb)]
    delivery_authentication_record: Value,
    #[diesel(sql_type = Text)]
    delivery_authentication_record_digest: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    outcome: Option<Value>,
    #[diesel(sql_type = Timestamptz)]
    received_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
}
#[derive(QueryableByName)]
struct AppletAuthoringPreviewRow {
    #[diesel(sql_type = Text)]
    subject_key: String,
    #[diesel(sql_type = Text)]
    basis_digest: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Jsonb)]
    signed_request: Value,
    #[diesel(sql_type = Timestamptz)]
    issued_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}
impl From<AppletRegistrationRow> for Value {
    fn from(row: AppletRegistrationRow) -> Self {
        row.record
    }
}
impl From<AppletTransactionReplayRow> for AppletTransactionReplayRecord {
    fn from(row: AppletTransactionReplayRow) -> Self {
        Self {
            applet_id: arkret_wire::AppletId::new(row.applet_id)
                .expect("stored applet transaction id must be canonical"),
            source_id: row.source_id,
            idempotency_key: row.idempotency_key,
            delivery_authentication_record: row.delivery_authentication_record,
            delivery_authentication_record_digest: row.delivery_authentication_record_digest,
            request_digest: row.request_digest,
            outcome: row.outcome,
            received_at: row.received_at,
            completed_at: row.completed_at,
        }
    }
}
impl From<AppletAuthoringPreviewRow> for AppletAuthoringPreviewRecord {
    fn from(row: AppletAuthoringPreviewRow) -> Self {
        Self {
            subject_key: row.subject_key,
            basis_digest: row.basis_digest,
            request_digest: row.request_digest,
            signed_request: row.signed_request,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
        }
    }
}
pub struct PgAppletStore {
    pub pool: PgPool,
}
#[async_trait]
impl AppletStore for PgAppletStore {
    async fn configuration_review_account(
        &self,
        request: &arkret_models_integration::ManagementReviewRequestBody,
    ) -> PersistenceResult<Option<arkret_wire::AccountId>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        crate::applet_configuration::review_account(&mut conn, request).await
    }

    async fn configuration_candidate_account(
        &self,
        event: &arkret_wire::Event,
    ) -> PersistenceResult<Option<arkret_wire::AccountId>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        crate::applet_configuration::candidate_account(&mut conn, event).await
    }

    async fn configuration_intent(
        &self,
        governor: &arkret_wire::DidCoreId,
        applet: &arkret_wire::AppletId,
        actor: &arkret_wire::ActorId,
        intent: &arkret_models_integration::AppletConfigurationIntent,
        current: &coland_storage::ManagementReviewCurrent,
    ) -> PersistenceResult<Option<arkret_models_integration::AppletConfigurationExecutionIntent>>
    {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(crate::applet_configuration::original_intent(
                conn, governor, applet, actor, intent, current,
            )
            .await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn configuration(
        &self,
        governor: &arkret_wire::DidCoreId,
        intent: &arkret_models_integration::AppletConfigurationExecutionIntent,
        command: arkret_models_integration::AppletConfigurationCommand,
        current: &coland_storage::ManagementReviewCurrent,
        ingress: &coland_storage::AppletConfigurationIngress,
    ) -> PersistenceResult<arkret_models_integration::AppletConfigurationOutcome> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(crate::applet_configuration::command(
                conn, governor, intent, command, current, ingress,
            )
            .await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn retain_configuration_source(
        &self,
        governor: &arkret_wire::DidCoreId,
        intent: &arkret_models_integration::AppletConfigurationExecutionIntent,
        source: &arkret_models_integration::AppletConfigurationExecutionOutcome,
        producer: &coland_storage::AppletEventProducerGuard,
        current: &coland_storage::ManagementReviewCurrent,
    ) -> PersistenceResult<arkret_models_integration::AppletConfigurationOutcome> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(crate::applet_configuration::source(
                conn, governor, intent, source, producer, current,
            )
            .await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn authority_material(
        &self,
        applet: &arkret_wire::AppletId,
        service: &arkret_wire::DidCoreId,
        station: &arkret_wire::DidCoreId,
        request: &arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialRequestBody,
    ) -> PersistenceResult<
        arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialOutcome,
    > {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                .execute(&mut *conn)
                .await?;
            Ok(
                crate::applet_authority_material::read(conn, applet, service, station, request)
                    .await?,
            )
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn issue_widget_token(
        &self,
        record: coland_storage::AppletWidgetTokenRecord,
    ) -> PersistenceResult<bool> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(crate::applet_widget_tokens::issue(conn, &record).await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn widget_tokens(
        &self,
        install: &coland_storage::AppletWidgetInstallSelector,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Vec<coland_storage::AppletWidgetTokenRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(crate::applet_widget_tokens::inventory(conn, install, at).await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn check_widget_token(
        &self,
        gate: &coland_storage::AppletWidgetTokenGateSelector,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<coland_storage::AppletWidgetTokenRecord> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(crate::applet_widget_tokens::check(conn, gate, at).await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn invalidate_widget_token(
        &self,
        install: &coland_storage::AppletWidgetInstallSelector,
        token_ref: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<coland_storage::AppletWidgetTokenInvalidation> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            Ok(crate::applet_widget_tokens::invalidate(conn, install, token_ref, at).await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn pending_authoring_completions(
        &self,
        limit: u32,
    ) -> PersistenceResult<Vec<coland_storage::AppletAuthoringCompletion>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        crate::applet_completion::pending(&mut conn, limit).await
    }
    async fn acknowledge_authoring_completion(
        &self,
        applet_id: &arkret_wire::AppletId,
        request_digest: &arkret_wire::Hash,
        idempotency_key: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            Ok(crate::applet_completion::acknowledge(
                conn,
                applet_id,
                request_digest,
                idempotency_key,
                at,
            )
            .await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
    async fn admit_authoring_unit(
        &self,
        input: coland_storage::AppletAuthoringUnitWrite,
        author: coland_storage::AppletCommitAuthor,
        attester: coland_storage::AppletResolutionAttester,
        finalize: coland_storage::AppletUnitFinalizer,
    ) -> PersistenceResult<coland_storage::AppletAuthoringUnitOutcome> {
        // Own the aggregate independently of the HTTP middleware poll stack.
        // A disconnected caller can recover its committed outcome by exact
        // retry; all checks and writes still share the one SQL transaction.
        let pool = self.pool.clone();
        tokio::spawn(async move {
            crate::applet_admission::admit_authoring_unit(&pool, input, author, attester, finalize)
                .await
        })
        .await
        .map_err(|error| {
            PersistenceError::Internal(format!("Applet admission task failed: {error}"))
        })?
    }

    async fn get_identity(
        &self,
        applet_id: &str,
        target_station_id: &str,
    ) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT record FROM applet_managed_identities \
             WHERE applet_id = $1 AND target_station_id = $2",
        )
        .bind::<Text, _>(applet_id)
        .bind::<Text, _>(target_station_id)
        .get_result::<AppletRegistrationRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(Value::from))
        .map_err(PersistenceError::database)
    }

    async fn get(
        &self,
        applet_id: &str,
        service_id: &str,
        effective_scope_key: &str,
    ) -> PersistenceResult<Option<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(applet_registration_select_sql(
            "WHERE applet_id = $1 AND effective_scope_key = $2 AND service_id = $3",
        ))
        .bind::<Text, _>(applet_id)
        .bind::<Text, _>(effective_scope_key)
        .bind::<Text, _>(service_id)
        .get_result::<AppletRegistrationRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(Value::from))
        .map_err(PersistenceError::database)
    }

    async fn compare_and_swap(
        &self,
        applet_id: &str,
        service_id: &str,
        effective_scope_key: &str,
        expected: &Value,
        replacement: Value,
    ) -> PersistenceResult<bool> {
        coland_storage::validate_applet_installation_record(expected)?;
        coland_storage::validate_applet_installation_record(&replacement)?;
        if expected
            .pointer("/package/service_id")
            .and_then(Value::as_str)
            != Some(service_id)
            || replacement
                .pointer("/package/service_id")
                .and_then(Value::as_str)
                != Some(service_id)
            || coland_storage::applet_id_from_record(expected)? != applet_id
            || coland_storage::applet_id_from_record(&replacement)? != applet_id
            || coland_storage::applet_effective_scope_key_from_record(&replacement)?
                != effective_scope_key
        {
            return Err(PersistenceError::Conflict(
                "schema_violation: Applet CAS cannot change applet_id or effective_scope"
                    .to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let current=sql_query("SELECT record FROM applet_installations WHERE applet_id=$1 AND effective_scope_key=$2 AND service_id=$3 FOR UPDATE")
                .bind::<Text,_>(applet_id).bind::<Text,_>(effective_scope_key).bind::<Text,_>(service_id)
                .get_result::<AppletRegistrationRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            if current.as_ref().map(|r|&r.record)!=Some(expected) {return Ok(false);}
            if expected.get("revoke_execution")!=replacement.get("revoke_execution")
                && expected.pointer("/revoke_execution/outcome/operation_id") != replacement.pointer("/revoke_execution/outcome/operation_id")
                && let Some(plan)=replacement.pointer("/revoke_execution/revoke_plan") {
                    let plan:arkret_models_integration::AppletRevokePlan=serde_json::from_value(plan.clone()).map_err(PersistenceError::database)?;
                    if matches!(plan.revoke_mode,arkret_wire::AppletRevokeMode::RevokeAll|arkret_wire::AppletRevokeMode::RevokeWidgetOnly) {
                        let install=coland_storage::AppletWidgetInstallSelector {
                            applet_id:plan.applet_id,effective_scope:plan.effective_scope,registration_epoch:plan.registration_epoch,
                            registration_event_ref:serde_json::from_value(expected.pointer("/install_response/registration_event_ref").cloned().ok_or_else(||PersistenceError::SchemaViolation("Applet registration Event is absent".into()))?).map_err(PersistenceError::database)?
                        };
                        let inventory=crate::applet_widget_tokens::inventory(conn,&install,chrono::Utc::now()).await?;
                        let actual=inventory.iter().map(|t|t.token_ref.as_str()).collect::<std::collections::BTreeSet<_>>();
                        let planned=plan.widget_token_refs.iter().map(|t|t.as_str()).collect::<std::collections::BTreeSet<_>>();
                        if actual!=planned {return Err(PersistenceError::Conflict("stale_state: widget inventory differs from the frozen revoke plan".into()).into());}
                    }
                }
            let updated=sql_query("UPDATE applet_installations SET record=$3,updated_at=NOW() WHERE applet_id=$1 AND effective_scope_key=$2 AND service_id=$4")
                .bind::<Text,_>(applet_id).bind::<Text,_>(effective_scope_key).bind::<Jsonb,_>(&replacement).bind::<Text,_>(service_id)
                .execute(conn).await.map_err(PersistenceError::database)?;
            Ok(updated==1)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn fence_installation(
        &self,
        applet_id: &str,
        service_id: &str,
        effective_scope_key: &str,
        target_station_id: &str,
        expected: &Value,
        replacement: Value,
        fenced_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<coland_storage::AppletInstallationFenceOutcome> {
        coland_storage::validate_applet_installation_record(expected)?;
        coland_storage::validate_applet_installation_record(&replacement)?;
        if expected
            .pointer("/package/service_id")
            .and_then(Value::as_str)
            != Some(service_id)
            || replacement
                .pointer("/package/service_id")
                .and_then(Value::as_str)
                != Some(service_id)
            || coland_storage::applet_id_from_record(expected)? != applet_id
            || coland_storage::applet_id_from_record(&replacement)? != applet_id
            || coland_storage::applet_effective_scope_key_from_record(&replacement)?
                != effective_scope_key
        {
            return Err(PersistenceError::Conflict(
                "schema_violation: Applet fence cannot change applet_id or effective_scope"
                    .to_owned(),
            ));
        }
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let fenced_at = Value::String(arkret_canonical::format_timestamp_canonical(fenced_at));
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // The durable identity winner is also the per-Applet revoke
            // linearization point. Without this row lock, concurrent revokes
            // of the last two active scopes can each observe the other scope
            // as active in its statement snapshot and neither would fence the
            // identity.
            let identity = sql_query(
                "SELECT record FROM applet_managed_identities \
                 WHERE applet_id = $1 AND target_station_id = $2 FOR UPDATE",
            )
            .bind::<Text, _>(applet_id)
            .bind::<Text, _>(target_station_id)
            .get_result::<AppletRegistrationRow>(&mut *conn)
            .await
            .optional()?;
            if identity.is_none() {
                return Err(PersistenceError::NotFound(format!(
                    "Applet identity winner missing for {applet_id}/{target_station_id}"
                ))
                .into());
            }

            let updated = sql_query(
                "UPDATE applet_installations SET record = $4, updated_at = NOW() \
                 WHERE applet_id = $1 AND effective_scope_key = $2 AND record = $3 AND service_id = $5",
            )
            .bind::<Text, _>(applet_id)
            .bind::<Text, _>(effective_scope_key)
            .bind::<Jsonb, _>(expected)
            .bind::<Jsonb, _>(&replacement)
            .bind::<Text, _>(service_id)
            .execute(&mut *conn)
            .await?;
            if updated == 0 {
                return Ok(coland_storage::AppletInstallationFenceOutcome {
                    updated: false,
                    globally_fenced: false,
                });
            }

            let has_active_scope = sql_query(
                "SELECT EXISTS (\
                     SELECT 1 FROM applet_installations \
                     WHERE applet_id = $1 AND record->>'revoked_at' IS NULL \
                       AND record->>'status' IN ('installed', 'partially_installed')\
                 ) AS present",
            )
            .bind::<Text, _>(applet_id)
            .get_result::<ExistsRow>(&mut *conn)
            .await?
            .present;
            if has_active_scope {
                return Ok(coland_storage::AppletInstallationFenceOutcome {
                    updated: true,
                    globally_fenced: false,
                });
            }

            let globally_fenced = sql_query(
                "UPDATE applet_managed_identities \
                 SET record = jsonb_set(record, '{globally_fenced_at}', $3, true) \
                 WHERE applet_id = $1 AND target_station_id = $2",
            )
            .bind::<Text, _>(applet_id)
            .bind::<Text, _>(target_station_id)
            .bind::<Jsonb, _>(&fenced_at)
            .execute(&mut *conn)
            .await?;
            debug_assert_eq!(globally_fenced, 1);
            Ok(coland_storage::AppletInstallationFenceOutcome {
                updated: true,
                globally_fenced: true,
            })
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn list(&self) -> PersistenceResult<Vec<Value>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(applet_registration_select_sql(
            "ORDER BY record->>'registered_at', applet_id, effective_scope_key",
        ))
        .load::<AppletRegistrationRow>(&mut *conn)
        .await
        .map(|rows| rows.into_iter().map(Value::from).collect())
        .map_err(PersistenceError::database)
    }

    async fn begin_transaction_replay(
        &self,
        record: AppletTransactionReplayRecord,
    ) -> PersistenceResult<AppletTransactionReplayBegin> {
        validate_delivery_binding(&record)?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        let inserted = sql_query(
            "INSERT INTO applet_transactions \
             (applet_id, source_id, idempotency_key, delivery_authentication_record, \
              delivery_authentication_record_digest, request_digest, outcome, received_at, completed_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (applet_id, source_id, idempotency_key) DO NOTHING",
        )
        .bind::<Text, _>(record.applet_id.as_str())
        .bind::<Text, _>(&record.source_id)
        .bind::<Text, _>(&record.idempotency_key)
        .bind::<Jsonb, _>(&record.delivery_authentication_record)
        .bind::<Text, _>(&record.delivery_authentication_record_digest)
        .bind::<Text, _>(&record.request_digest)
        .bind::<Nullable<Jsonb>, _>(&record.outcome)
        .bind::<Timestamptz, _>(record.received_at)
        .bind::<Nullable<Timestamptz>, _>(record.completed_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if inserted == 1 {
            return Ok(AppletTransactionReplayBegin::Fresh);
        }
        let existing = sql_query(applet_transaction_replay_select_sql())
            .bind::<Text, _>(record.applet_id.as_str())
            .bind::<Text, _>(&record.source_id)
            .bind::<Text, _>(&record.idempotency_key)
            .get_result::<AppletTransactionReplayRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .map(AppletTransactionReplayRecord::from)
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "applet transaction conflict row disappeared after insert".to_owned(),
                )
            })?;
        validate_delivery_binding(&existing)?;
        if record.delivery_authentication_record_digest
            != existing.delivery_authentication_record_digest
            || record.request_digest != existing.request_digest
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: Applet transaction body or authenticated identity changed"
                    .to_owned(),
            ));
        }
        Ok(AppletTransactionReplayBegin::Existing(Box::new(existing)))
    }

    async fn complete_transaction_replay(
        &self,
        applet_id: &str,
        source_id: &str,
        idempotency_key: &str,
        outcome: Value,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "UPDATE applet_transactions \
             SET outcome = $4, completed_at = NOW() \
             WHERE applet_id = $1 AND source_id = $2 AND idempotency_key = $3",
        )
        .bind::<Text, _>(applet_id)
        .bind::<Text, _>(source_id)
        .bind::<Text, _>(idempotency_key)
        .bind::<Jsonb, _>(&outcome)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)
        .and_then(|updated| {
            if updated == 0 {
                Err(PersistenceError::NotFound(format!(
                    "applet transaction replay missing for {applet_id}/{source_id}/{idempotency_key}"
                )))
            } else {
                Ok(())
            }
        })
    }

    async fn issue_authoring_preview(
        &self,
        candidate: AppletAuthoringPreviewRecord,
    ) -> PersistenceResult<AppletAuthoringPreviewRecord> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 1634758768))")
                .bind::<Text, _>(&candidate.subject_key)
                .execute(&mut *conn)
                .await?;
            let current = sql_query(
                "SELECT subject_key, basis_digest, request_digest, signed_request, issued_at, expires_at \
                 FROM applet_authoring_previews WHERE subject_key = $1 AND status = 'current'",
            )
            .bind::<Text, _>(&candidate.subject_key)
            .get_result::<AppletAuthoringPreviewRow>(&mut *conn)
            .await
            .optional()?;
            if let Some(current) = current
                && current.basis_digest == candidate.basis_digest
                && current.expires_at > candidate.issued_at
            {
                return Ok(current.into());
            }
            sql_query(
                "UPDATE applet_authoring_previews SET status = 'superseded', superseded_at = NOW() \
                 WHERE subject_key = $1 AND status = 'current'",
            )
            .bind::<Text, _>(&candidate.subject_key)
            .execute(&mut *conn)
            .await?;
            sql_query(
                "INSERT INTO applet_authoring_previews \
                 (subject_key, basis_digest, request_digest, signed_request, issued_at, expires_at, status) \
                 VALUES ($1, $2, $3, $4, $5, $6, 'current') \
                 ON CONFLICT (subject_key, request_digest) DO UPDATE SET \
                 basis_digest = EXCLUDED.basis_digest, signed_request = EXCLUDED.signed_request, \
                 issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at, \
                 status = 'current', superseded_at = NULL, committed_at = NULL",
            )
            .bind::<Text, _>(&candidate.subject_key)
            .bind::<Text, _>(&candidate.basis_digest)
            .bind::<Text, _>(&candidate.request_digest)
            .bind::<Jsonb, _>(&candidate.signed_request)
            .bind::<Timestamptz, _>(candidate.issued_at)
            .bind::<Timestamptz, _>(candidate.expires_at)
            .execute(&mut *conn)
            .await?;
            Ok(candidate)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn current_authoring_preview(
        &self,
        subject_key: &str,
    ) -> PersistenceResult<Option<AppletAuthoringPreviewRecord>> {
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        sql_query(
            "SELECT subject_key, basis_digest, request_digest, signed_request, issued_at, expires_at \
             FROM applet_authoring_previews WHERE subject_key = $1 AND status = 'current'",
        )
        .bind::<Text, _>(subject_key)
        .get_result::<AppletAuthoringPreviewRow>(&mut *conn)
        .await
        .optional()
        .map(|row| row.map(AppletAuthoringPreviewRecord::from))
        .map_err(PersistenceError::database)
    }
}

fn validate_delivery_binding(record: &AppletTransactionReplayRecord) -> PersistenceResult<()> {
    let typed: arkret_models_integration::AppletDeliveryAuthenticationRecord =
        serde_json::from_value(record.delivery_authentication_record.clone())
            .map_err(PersistenceError::database)?;
    let digest = typed.stable_digest().map_err(PersistenceError::database)?;
    if digest.as_str() != record.delivery_authentication_record_digest
        || typed.source_id.as_str() != record.source_id
        || typed.idempotency_key != record.idempotency_key
        || typed.operation_id != arkret_wire::ServiceOperationId::EdgeAppletCommandTransactionV1
        || typed.direction
            != arkret_models_integration::AppletDeliveryDirection::AppletToArkretInbound
    {
        return Err(PersistenceError::Conflict(
            "schema_violation: delivery record and stable replay binding disagree".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transaction_replay_retains_verified_delivery_record() {
        let pool = crate::test_database::contract_pool().await;
        let store = PgAppletStore { pool };
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let idempotency_key = format!("delivery-record-{nonce}");
        let delivery_authentication_record = serde_json::json!({
            "operation_id": "ak.edge.applet.command.transaction.v1",
            "direction": "applet_to_arkret_inbound",
            "source_id": "ak:did_core:web:applet.example",
            "destination_id": "ak:did_core:web:station.example",
            "signature_label": "sig1",
            "verification_method": "did:web:applet.example#key-1",
            "verification_key_digest": format!("sha256:{}", "a".repeat(64)),
            "signature_algorithm": "ed25519",
            "registration_epoch": format!("sha256:{}", "c".repeat(64)),
            "idempotency_key": idempotency_key,
            "content_digest": "sha-256=:Zm94:",
            "covered_components": [
                "@method", "@target-uri", "@authority", "content-digest",
                "arkret-operation", "source-service-id", "destination-service-id",
                "idempotency-key"
            ],
            "created": 1_790_000_000,
            "expires": 1_790_000_300,
        });
        let typed: arkret_models_integration::AppletDeliveryAuthenticationRecord =
            serde_json::from_value(delivery_authentication_record.clone()).unwrap();
        let delivery_authentication_record_digest = typed.stable_digest().unwrap().to_string();
        let record = AppletTransactionReplayRecord {
            applet_id: arkret_wire::AppletId::new("ak:applet:01974100-0000-7000-8000-000000000001")
                .unwrap(),
            source_id: "ak:did_core:web:applet.example".to_owned(),
            idempotency_key,
            delivery_authentication_record,
            delivery_authentication_record_digest,
            request_digest: format!("sha256:{}", "b".repeat(64)),
            outcome: None,
            received_at: chrono::Utc::now(),
            completed_at: None,
        };
        assert!(matches!(
            store
                .begin_transaction_replay(record.clone())
                .await
                .unwrap(),
            AppletTransactionReplayBegin::Fresh
        ));
        let mut fresh = record.clone();
        fresh.delivery_authentication_record["created"] = serde_json::json!(1_790_000_060);
        fresh.delivery_authentication_record["expires"] = serde_json::json!(1_790_000_360);
        let AppletTransactionReplayBegin::Existing(replay) =
            store.begin_transaction_replay(fresh.clone()).await.unwrap()
        else {
            panic!("the second delivery must read the durable replay record")
        };
        assert_eq!(
            replay.delivery_authentication_record,
            record.delivery_authentication_record
        );
        assert_eq!(
            replay.delivery_authentication_record_digest,
            record.delivery_authentication_record_digest
        );
        assert_eq!(replay.request_digest, record.request_digest);
        let mut changed_key = fresh.clone();
        changed_key.delivery_authentication_record["verification_key_digest"] =
            serde_json::json!(format!("sha256:{}", "d".repeat(64)));
        let typed: arkret_models_integration::AppletDeliveryAuthenticationRecord =
            serde_json::from_value(changed_key.delivery_authentication_record.clone()).unwrap();
        changed_key.delivery_authentication_record_digest =
            typed.stable_digest().unwrap().to_string();
        assert!(
            matches!(store.begin_transaction_replay(changed_key.clone()).await,
            Err(PersistenceError::Conflict(detail)) if detail.starts_with("duplicate_conflict:"))
        );
        changed_key.delivery_authentication_record_digest =
            fresh.delivery_authentication_record_digest.clone();
        assert!(matches!(store.begin_transaction_replay(changed_key).await,
            Err(PersistenceError::Conflict(detail)) if detail.starts_with("schema_violation:")));
        let mut changed_body = fresh;
        changed_body.request_digest = format!("sha256:{}", "e".repeat(64));
        assert!(matches!(store.begin_transaction_replay(changed_body).await,
            Err(PersistenceError::Conflict(detail)) if detail.starts_with("duplicate_conflict:")));
    }
}
