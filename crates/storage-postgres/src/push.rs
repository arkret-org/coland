use super::{
    AsyncPgConnection, Bool, JsonPayloadRow, Jsonb, Nullable, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PushDeviceStore, RunQueryDsl, Text, Timestamptz, Value, async_trait,
    pg_conn, sql_query,
};
use crate::PgTransactionError;
#[derive(diesel::QueryableByName)]
struct PushSourceRow {
    #[diesel(sql_type=Jsonb)]
    payload: Value,
    #[diesel(sql_type=Jsonb)]
    device_authorization: Value,
    #[diesel(sql_type=Bool)]
    public_handoff: bool,
}
pub struct PgPushDeviceStore {
    pub pool: PgPool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PushDeviceRouteWriteMode {
    AllowReplace,
    RequireExact,
}

pub(crate) fn push_device_lock_key(account: &arkret_wire::AccountId, device_id: &str) -> String {
    format!("push:{}:{device_id}", account.principal_id)
}

/// Lock and write one exact local push route on a caller-owned transaction.
/// The caller must re-check the device revocation gate before invoking this
/// helper; keeping that check outside makes the handoff UOW's lock order
/// explicit rather than silently taking the route lock first.
pub(crate) async fn write_push_device_route_in_transaction(
    conn: &mut AsyncPgConnection,
    authorization: &coland_storage::DeviceRevocationGateSelector,
    mut registration: arkret_models_integration::PushRegistrationRecord,
    at: chrono::DateTime<chrono::Utc>,
    mode: PushDeviceRouteWriteMode,
    public_handoff: bool,
) -> PersistenceResult<()> {
    registration
        .account_id
        .validate()
        .map_err(|error| PersistenceError::Internal(error.to_string()))?;
    if registration.push_gateway.is_empty() || registration.push_route_id.is_empty() {
        return Err(PersistenceError::Internal(
            "push registration requires gateway and route".to_owned(),
        ));
    }
    if authorization.principal_id != registration.account_id.principal_id
        || authorization.station_id != registration.account_id.station_id
        || authorization.device_id != registration.device_id.as_str()
    {
        return Err(PersistenceError::Conflict(
            "push registration differs from its verified device authorization".into(),
        ));
    }
    let binding = serde_json::to_value(authorization).map_err(PersistenceError::database)?;
    let account =
        serde_json::to_value(&registration.account_id).map_err(PersistenceError::database)?;
    // Serialize replacement and unregistration for this exact account/device.
    let lock_key = push_device_lock_key(&registration.account_id, registration.device_id.as_str());
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(&lock_key)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let previous = sql_query(
        "SELECT payload,device_authorization,public_handoff FROM push_devices \
         WHERE payload->'account_id' = $1 AND device_id = $2 \
           AND payload->>'push_route_id' = $3 FOR UPDATE",
    )
    .bind::<Jsonb, _>(&account)
    .bind::<Text, _>(registration.device_id.as_str())
    .bind::<Text, _>(&registration.push_route_id)
    .get_result::<PushSourceRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    registration.retained_push_targets.clear();
    if let Some(previous) = &previous {
        if previous.public_handoff && !public_handoff {
            return Err(PersistenceError::Conflict(
                "cas_conflict: local registration cannot replace a public handoff route".to_owned(),
            ));
        }
        let old: arkret_models_integration::PushRegistrationRecord =
            serde_json::from_value(previous.payload.clone()).map_err(PersistenceError::database)?;
        // Aliases survive salt rotation only; route/provider replacement never
        // grants an old target access to a newly registered delivery token.
        if previous.device_authorization == binding
            && old.push_key == registration.push_key
            && old.push_gateway == registration.push_gateway
        {
            registration.retained_push_targets = old
                .retained_push_targets
                .into_iter()
                .filter(|entry| at < entry.retained_until)
                .collect();
            if old.push_target_id != registration.push_target_id {
                registration.retained_push_targets.push(
                    arkret_models_integration::RetainedPushTarget {
                        push_target_id: old.push_target_id,
                        retained_until: at + chrono::Duration::hours(24),
                    },
                );
            }
        }
    }
    let payload = serde_json::to_value(&registration).map_err(PersistenceError::database)?;
    if previous.as_ref().is_some_and(|previous| {
        previous.payload == payload
            && previous.device_authorization == binding
            && previous.public_handoff == public_handoff
    }) {
        return Ok(());
    }
    if mode == PushDeviceRouteWriteMode::RequireExact {
        return Err(PersistenceError::Conflict(
            "cas_conflict: verified push receipt replay has no exact local route".to_owned(),
        ));
    }
    sql_query(
        "INSERT INTO push_devices \
         (id, actor_id, device_id, push_gateway, push_key, platform, app_id, payload, \
          device_authorization, updated_at, public_handoff) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
         ON CONFLICT ((payload->'account_id'), device_id, (payload->>'push_route_id')) \
         DO UPDATE SET id=EXCLUDED.id, actor_id=EXCLUDED.actor_id, \
           push_gateway=EXCLUDED.push_gateway, push_key=EXCLUDED.push_key, \
           platform=EXCLUDED.platform, app_id=EXCLUDED.app_id, payload=EXCLUDED.payload, \
           device_authorization=EXCLUDED.device_authorization, updated_at=EXCLUDED.updated_at, \
           public_handoff=EXCLUDED.public_handoff",
    )
    .bind::<Text, _>(registration.registration_id.as_str())
    .bind::<Text, _>(registration.account_id.principal_id.as_str())
    .bind::<Text, _>(registration.device_id.as_str())
    .bind::<Text, _>(&registration.push_gateway)
    .bind::<Text, _>(registration.push_key.as_str())
    .bind::<Nullable<Text>, _>(&registration.platform)
    .bind::<Nullable<Text>, _>(&registration.app_id)
    .bind::<Jsonb, _>(&payload)
    .bind::<Jsonb, _>(&binding)
    .bind::<Timestamptz, _>(at)
    .bind::<Bool, _>(public_handoff)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

#[async_trait]
impl PushDeviceStore for PgPushDeviceStore {
    async fn register(
        &self,
        authorization: &coland_storage::DeviceRevocationGateSelector,
        device: Value,
    ) -> PersistenceResult<()> {
        use diesel_async::AsyncConnection;
        let registration: arkret_models_integration::PushRegistrationRecord =
            serde_json::from_value(device).map_err(|error| {
                PersistenceError::Internal(format!(
                    "invalid authenticated push registration: {error}"
                ))
            })?;
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::ensure_gate_allowed_in_transaction(conn, authorization).await?;
            let at = chrono::Utc::now();
            write_push_device_route_in_transaction(
                conn,
                authorization,
                registration,
                at,
                PushDeviceRouteWriteMode::AllowReplace,
                false,
            )
            .await
            .map_err(PgTransactionError::from)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn unregister(
        &self,
        account: &arkret_wire::AccountId,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> PersistenceResult<usize> {
        use diesel_async::AsyncConnection;
        let account_value = serde_json::to_value(account).map_err(PersistenceError::database)?;
        let lock_key = push_device_lock_key(account, device_id);
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))").bind::<Text,_>(&lock_key).execute(&mut *conn).await.map_err(PersistenceError::database)?;
            sql_query("DELETE FROM push_devices WHERE public_handoff=FALSE AND payload->'account_id' = $1 AND device_id = $2 AND ($3 IS NULL OR push_key = $3) AND ($4 IS NULL OR app_id = $4)")
                .bind::<Jsonb,_>(&account_value).bind::<Text,_>(device_id).bind::<Nullable<Text>,_>(push_key).bind::<Nullable<Text>,_>(app_id)
                .execute(&mut *conn).await.map_err(PgTransactionError::from)
        }).await.map_err(PgTransactionError::into_persistence)
    }

    async fn purge_principal_device(
        &self,
        actor: &str,
        device_id: &str,
    ) -> PersistenceResult<usize> {
        use diesel_async::AsyncConnection;
        let lock_key = format!("push:{actor}:{device_id}");
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&lock_key)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            sql_query("DELETE FROM push_devices WHERE public_handoff=FALSE AND actor_id = $1 AND device_id = $2")
                .bind::<Text, _>(actor)
                .bind::<Text, _>(device_id)
                .execute(&mut *conn)
                .await
                .map_err(PgTransactionError::from)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>> {
        let now = chrono::Utc::now();
        let mut conn = pg_conn(&self.pool)
            .await
            .map_err(PersistenceError::database)?;
        use diesel_async::AsyncConnection;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let sources = sql_query(
                "SELECT payload,device_authorization,public_handoff \
                 FROM push_devices ORDER BY updated_at,id",
            )
            .load::<PushSourceRow>(conn)
            .await?;
            let bindings = sources
                .iter()
                .map(|row| {
                    serde_json::from_value::<coland_storage::DeviceRevocationGateSelector>(
                        row.device_authorization.clone(),
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(PersistenceError::database)?;
            crate::device_revocations::lock_artifact_devices_in_transaction(
                conn,
                &bindings.iter().collect::<Vec<_>>(),
            )
            .await?;
            let mut visible = Vec::new();
            for (source, binding) in sources.into_iter().zip(bindings) {
                if crate::gate_status_in_transaction(conn, &binding).await?
                    != coland_storage::DeviceRevocationGateStatus::Active
                {
                    continue;
                }
                // Re-read under the same device lock as replacement/cleanup.
                let id = source
                    .payload
                    .get("registration_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        PersistenceError::SchemaViolation("push registration id missing".into())
                    })?;
                if let Some(row) = sql_query(
                    "SELECT payload FROM push_devices WHERE id=$1 AND device_authorization=$2",
                )
                .bind::<Text, _>(id)
                .bind::<Jsonb, _>(&source.device_authorization)
                .get_result::<JsonPayloadRow>(conn)
                .await
                .optional()?
                {
                    let registration: arkret_models_integration::PushRegistrationRecord =
                        serde_json::from_value(row.payload.clone())
                            .map_err(PersistenceError::database)?;
                    if source.public_handoff {
                        // The lifecycle writer takes an exclusive lock on the
                        // same account row. A completed deactivation cannot
                        // leave a public route deliverable while its revoke
                        // fanout and Gateway receipt are still pending.
                        match crate::push_handoff::ensure_active_account_in_transaction(
                            conn,
                            &registration.account_id,
                        )
                        .await
                        {
                            Ok(()) => {}
                            Err(PersistenceError::Conflict(_)) => continue,
                            Err(error) => return Err(error.into()),
                        }
                    }
                    // Delivery reads enforce the validity boundary after the
                    // device lock and exact-row re-read, independently from
                    // the asynchronous durable tombstone sweep.
                    if registration.expires_at.is_some_and(|expiry| expiry <= now) {
                        continue;
                    }
                    visible.push(row.payload);
                }
            }
            Ok(visible)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_authorization_history::{device, did_web_station};
    use crate::pcr_genesis::PcrGenesisFixture;

    #[tokio::test]
    async fn postgres_push_registration_atomic_rotation_and_exact_account_removal() {
        let database = crate::test_database::TestDatabase::lease().await;
        let store = PgPushDeviceStore {
            pool: database.pool(),
        };
        let station_id =
            arkret_wire::DidCoreId::new("ak:did_core:web:push-registration.example").unwrap();
        let source = PcrGenesisFixture::new(did_web_station(&station_id));
        {
            let mut conn = store.pool.get().await.unwrap();
            sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
                .bind::<Text, _>(station_id.as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let authorization = source
            .admit_founding_device(&crate::PgPersistenceStore::new(store.pool.clone()))
            .await
            .expect("accepted PCR genesis");
        let mut record: arkret_models_integration::PushRegistrationRecord = serde_json::from_value(serde_json::json!({
            "registration_id":"push_registration:first", "account_id":{"principal_id":"ak:did_core:web:alice.example", "station_id":"ak:did_core:web:station.example"},
            "device_id":"ak:device:0196419b-0000-7000-8000-000000000001",
            "push_gateway":"https://push.example/", "push_key":"token", "platform":null,
            "app_id":"app", "visible_notification_opt_in":false, "push_route_id":"app",
            "push_target_id":"ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "salt_epoch_id":"first", "expires_at":null, "retained_push_targets":[]
        })).unwrap();
        record.account_id = source.history.account.clone();
        record.device_id = device(1);
        assert_eq!(authorization.device_id, record.device_id.as_str());
        store
            .register(&authorization, serde_json::to_value(&record).unwrap())
            .await
            .unwrap();
        let first_target = record.push_target_id.clone();
        record.registration_id =
            arkret_wire::OpaqueLocalId::new("push_registration:second").unwrap();
        record.push_target_id = "ak:pseudonym:push:lg8aqJ2eJjms1GQpkzloxGn8F802f8RfmfmfsC85eRo"
            .parse()
            .unwrap();
        record.salt_epoch_id = "second".to_owned();
        record.visible_notification_opt_in = true;
        store
            .register(&authorization, serde_json::to_value(&record).unwrap())
            .await
            .unwrap();
        let rows = store.snapshot_all().await.unwrap();
        assert_eq!(rows.len(), 1);
        let rotated: arkret_models_integration::PushRegistrationRecord =
            serde_json::from_value(rows[0].clone()).unwrap();
        assert!(rotated.accepts_target(&first_target, chrono::Utc::now()));
        assert!(rotated.visible_notification_opt_in);
        assert!(!rotated.accepts_target(
            &first_target,
            chrono::Utc::now() + chrono::Duration::hours(25)
        ));
        record.push_key = arkret_models_integration::PushKey::new("new-token").unwrap();
        record.visible_notification_opt_in = false;
        store
            .register(&authorization, serde_json::to_value(&record).unwrap())
            .await
            .unwrap();
        let rows = store.snapshot_all().await.unwrap();
        let replaced: arkret_models_integration::PushRegistrationRecord =
            serde_json::from_value(rows[0].clone()).unwrap();
        assert!(replaced.retained_push_targets.is_empty());
        assert!(!replaced.visible_notification_opt_in);
        record.expires_at = Some(chrono::Utc::now() - chrono::Duration::milliseconds(1));
        store
            .register(&authorization, serde_json::to_value(&record).unwrap())
            .await
            .unwrap();
        assert!(
            store.snapshot_all().await.unwrap().is_empty(),
            "an expired route is never visible to the delivery snapshot"
        );
        record.expires_at = None;
        store
            .register(&authorization, serde_json::to_value(&record).unwrap())
            .await
            .unwrap();
        let mut wrong_account = record.account_id.clone();
        wrong_account.station_id = "ak:did_core:web:other.example".parse().unwrap();
        assert_eq!(
            store
                .unregister(&wrong_account, record.device_id.as_str(), None, None)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .unregister(
                    &record.account_id,
                    record.device_id.as_str(),
                    Some("token"),
                    None
                )
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .unregister(&record.account_id, record.device_id.as_str(), None, None)
                .await
                .unwrap(),
            1
        );
        assert!(store.snapshot_all().await.unwrap().is_empty());
    }
}
