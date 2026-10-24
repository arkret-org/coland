use coland_storage::{
    DeviceRevocationCleanupIntent, DeviceRevocationGateLinearization,
    DeviceRevocationGateLinearizationRequest, DeviceRevocationGateSelector,
    DeviceRevocationGateStatus, DeviceRevocationStore, DeviceRevocationTargetRecord,
    DeviceRevocationTransition, DeviceRevocationTransitionDecision, PersistenceError,
    PersistenceResult, classify_device_revocation_transition, selector_comparison_status,
};
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection};
use horme::{OptionalExtension, RunQueryDsl};

use crate::{PgPool, PgTransactionError, async_trait, pg_conn};

pub struct PgDeviceRevocationStore {
    pub pool: PgPool,
}

#[cfg(feature = "test-support")]
impl PgDeviceRevocationStore {
    /// Exercise the exact current-binding gate used by production write units.
    #[doc(hidden)]
    pub async fn test_gate_status_in_transaction(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> PersistenceResult<DeviceRevocationGateStatus> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async |conn| {
            Ok(gate_status_in_transaction(conn, selector).await?)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

#[derive(QueryableByName)]
struct TargetRow {
    #[diesel(sql_type = Jsonb)]
    selector: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    committed_ref: serde_json::Value,
    #[diesel(sql_type = Timestamptz)]
    committed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct LinearizationRow {
    #[diesel(sql_type = Jsonb)]
    request_json: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    status_json: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    linearization_seq: i64,
    #[diesel(sql_type = Timestamptz)]
    linearized_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct CleanupRow {
    #[diesel(sql_type = Jsonb)]
    committed_ref: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    selector: serde_json::Value,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    material_cleanup_completed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    mls_obligation_completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn decode<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
    what: &str,
) -> PersistenceResult<T> {
    serde_json::from_value(value)
        .map_err(|error| PersistenceError::Internal(format!("stored {what} is invalid: {error}")))
}

fn target(row: TargetRow) -> PersistenceResult<DeviceRevocationTargetRecord> {
    Ok(DeviceRevocationTargetRecord {
        selector: decode(row.selector, "device revocation selector")?,
        revoke_ref: decode(row.committed_ref, "device revocation commit ref")?,
        committed_at: row.committed_at,
    })
}

#[async_trait]
impl DeviceRevocationStore for PgDeviceRevocationStore {
    async fn applet_managed_event_producer(
        &self,
        event: &arkret_wire::Event,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<coland_storage::AppletManagedDeviceAuthority>> {
        crate::realm_actor_device_authority::for_event(&self.pool, event, now).await
    }

    async fn consume_applet_managed_device_nonce(
        &self,
        expected: &coland_storage::AppletManagedDeviceAuthority,
        metadata: &arkret_models_integration::AppletManagedDeviceMetadata,
        retain_until: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<coland_storage::AppletManagedDeviceAuthority> {
        crate::realm_actor_device_authority::consume_nonce(
            &self.pool,
            expected,
            metadata,
            retain_until,
        )
        .await
    }

    async fn applet_managed_device_authority(
        &self,
        account: &arkret_wire::ActorId,
        device_id: &arkret_wire::DeviceId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Option<coland_storage::AppletManagedDeviceAuthority>> {
        crate::realm_actor_device_authority::current(&self.pool, account, device_id, now).await
    }

    async fn pcr_device_generation(
        &self,
        account: &arkret_wire::AccountId,
    ) -> PersistenceResult<Option<coland_storage::PcrDeviceGeneration>> {
        crate::pcr_device_status_reader::confirmed_pcr_generation(&self.pool, account).await
    }

    async fn pcr_device_admission(
        &self,
        account: &arkret_wire::AccountId,
        device_id: &arkret_wire::DeviceId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<arkret_wire::AccountDeviceRevocationAdmissionDecision> {
        let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut(
            &self.pool, account, device_id, now,
        )
        .await?
        .ok_or_else(|| {
            PersistenceError::SchemaViolation(
                "PCR device has no confirmed same-cut status".to_owned(),
            )
        })?;
        Ok(cut.admission())
    }

    async fn pcr_device_authorization_key(
        &self,
        account: &arkret_wire::AccountId,
        device_id: &arkret_wire::DeviceId,
    ) -> PersistenceResult<Option<arkret_wire::DidKey>> {
        let mut conn = pg_conn(&self.pool).await?;
        let cut = crate::pcr_device_revocation_proposals::confirmed_pcr_device_cut_in_connection(
            &mut conn, account, device_id,
        )
        .await?;
        cut.and_then(|cut| cut.authorization)
            .map(|authorization| {
                arkret_wire::DidKey::new(authorization.payload.device_public_key_did.into_string())
                    .map_err(|error| {
                        PersistenceError::SchemaViolation(format!(
                            "accepted PCR device authorization key is not did:key: {error}"
                        ))
                    })
            })
            .transpose()
    }

    async fn gate_status(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> PersistenceResult<DeviceRevocationGateStatus> {
        let mut conn = crate::pg_db(&self.pool);
        let row = sql_query(
            "SELECT selector, committed_ref, committed_at FROM device_revocation_targets \
             WHERE selector = $1 ORDER BY committed_at DESC LIMIT 1",
        )
        .bind::<Jsonb, _>(serde_json::to_value(selector).map_err(PersistenceError::database)?)
        .get_result::<TargetRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        Ok(match row.map(target).transpose()? {
            Some(record) => DeviceRevocationGateStatus::Revoked {
                revoke_ref: record.revoke_ref,
                committed_at: record.committed_at,
            },
            None => DeviceRevocationGateStatus::Active,
        })
    }

    async fn list_targets(
        &self,
        selector: &DeviceRevocationGateSelector,
    ) -> PersistenceResult<Vec<DeviceRevocationTargetRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT selector, committed_ref, committed_at FROM device_revocation_targets \
             WHERE selector = $1 ORDER BY committed_at",
        )
        .bind::<Jsonb, _>(serde_json::to_value(selector).map_err(PersistenceError::database)?)
        .load::<TargetRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(target)
        .collect()
    }

    async fn target_for_event(
        &self,
        event_id: &arkret_wire::EventId,
    ) -> PersistenceResult<Option<DeviceRevocationTargetRecord>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT selector, committed_ref, committed_at FROM device_revocation_targets \
             WHERE event_id = $1",
        )
        .bind::<Text, _>(event_id.as_str())
        .get_result::<TargetRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(target)
        .transpose()
    }

    async fn linearize_gate(
        &self,
        request: DeviceRevocationGateLinearizationRequest,
    ) -> PersistenceResult<DeviceRevocationGateLinearization> {
        let request_json = serde_json::to_value(&request).map_err(PersistenceError::database)?;
        let selector_json = request
            .origin_current_selector
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(PersistenceError::database)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            if let Some(existing) = sql_query(
                "SELECT request_json, status_json, linearization_seq, linearized_at, expires_at \
                 FROM device_revocation_gate_receipts \
                 WHERE principal_id=$1 AND station_id=$2 AND device_id=$3 \
                   AND action_class=$4 AND intent_digest=$5",
            )
            .bind::<Text, _>(request.principal_id.as_str())
            .bind::<Text, _>(request.station_id.as_str())
            .bind::<Text, _>(&request.device_id)
            .bind::<Text, _>(request.action_class.as_str())
            .bind::<Text, _>(&request.intent_digest)
            .get_result::<LinearizationRow>(&mut *conn)
            .await
            .optional()?
            {
                if existing.request_json != request_json {
                    return Err(PersistenceError::Conflict(
                        "duplicate_conflict: device gate intent changed".to_owned(),
                    )
                    .into());
                }
                return Ok(DeviceRevocationGateLinearization {
                    request,
                    status: decode(existing.status_json, "device gate status")?,
                    linearization_seq: u64::try_from(existing.linearization_seq).map_err(|_| {
                        PersistenceError::Internal("negative gate sequence".to_owned())
                    })?,
                    linearized_at: existing.linearized_at,
                    expires_at: existing.expires_at,
                });
            }
            let current = request.origin_current_selector.as_ref();
            let mut status = selector_comparison_status(&request, current)
                .unwrap_or(DeviceRevocationGateStatus::Active);
            if matches!(status, DeviceRevocationGateStatus::Active)
                && current.is_some()
                && let Some(row) = sql_query(
                    "SELECT selector, committed_ref, committed_at FROM device_revocation_targets \
                     WHERE selector=$1 ORDER BY committed_at DESC LIMIT 1",
                )
                .bind::<Jsonb, _>(selector_json.as_ref().expect("selector JSON exists"))
                .get_result::<TargetRow>(&mut *conn)
                .await
                .optional()?
            {
                let record = target(row)?;
                status = DeviceRevocationGateStatus::Revoked {
                    revoke_ref: record.revoke_ref,
                    committed_at: record.committed_at,
                };
            }
            let sequence = sql_query(
                "INSERT INTO device_revocation_linearization_heads \
                 (principal_id, station_id, device_id, last_seq, updated_at) \
                 VALUES ($1,$2,$3,1,$4) ON CONFLICT (principal_id,station_id,device_id) \
                 DO UPDATE SET last_seq=device_revocation_linearization_heads.last_seq+1, updated_at=$4 \
                 RETURNING last_seq AS linearization_seq",
            )
            .bind::<Text, _>(request.principal_id.as_str())
            .bind::<Text, _>(request.station_id.as_str())
            .bind::<Text, _>(&request.device_id)
            .bind::<Timestamptz, _>(request.requested_at)
            .get_result::<SequenceRow>(&mut *conn)
            .await?
            .linearization_seq;
            let expires_at = request.requested_at + chrono::TimeDelta::seconds(30);
            let status_json = serde_json::to_value(&status).map_err(PersistenceError::database)?;
            sql_query(
                "INSERT INTO device_revocation_gate_receipts \
                 (principal_id,station_id,device_id,action_class,intent_digest,request_json,status_json,linearization_seq,linearized_at,expires_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            )
            .bind::<Text, _>(request.principal_id.as_str())
            .bind::<Text, _>(request.station_id.as_str())
            .bind::<Text, _>(&request.device_id)
            .bind::<Text, _>(request.action_class.as_str())
            .bind::<Text, _>(&request.intent_digest)
            .bind::<Jsonb, _>(&request_json)
            .bind::<Jsonb, _>(&status_json)
            .bind::<BigInt, _>(sequence)
            .bind::<Timestamptz, _>(request.requested_at)
            .bind::<Timestamptz, _>(expires_at)
            .execute(&mut *conn)
            .await?;
            Ok(DeviceRevocationGateLinearization {
                request,
                status,
                linearization_seq: u64::try_from(sequence).map_err(|_| {
                    PersistenceError::Internal("negative gate sequence".to_owned())
                })?,
                linearized_at: expires_at - chrono::TimeDelta::seconds(30),
                expires_at,
            })
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn commit_revocation(
        &self,
        transition: &DeviceRevocationTransition,
    ) -> PersistenceResult<DeviceRevocationTransitionDecision> {
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            commit_revocation_in_connection(conn, transition).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn pending_cleanup_intents(
        &self,
        limit: usize,
    ) -> PersistenceResult<Vec<DeviceRevocationCleanupIntent>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query(
            "SELECT committed_ref,selector,created_at,material_cleanup_completed_at,mls_obligation_completed_at \
             FROM device_revocation_cleanup_intents \
             WHERE material_cleanup_completed_at IS NULL OR mls_obligation_completed_at IS NULL \
             ORDER BY created_at LIMIT $1",
        )
        .bind::<BigInt, _>(i64::try_from(limit).unwrap_or(i64::MAX))
        .load::<CleanupRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(|row| {
            Ok(DeviceRevocationCleanupIntent {
                revoke_ref: decode(row.committed_ref, "cleanup commit ref")?,
                selector: decode(row.selector, "cleanup selector")?,
                created_at: row.created_at,
                material_cleanup_completed_at: row.material_cleanup_completed_at,
                mls_obligation_completed_at: row.mls_obligation_completed_at,
            })
        })
        .collect()
    }

    async fn complete_material_cleanup(
        &self,
        event_id: &arkret_wire::EventId,
        completed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        complete(
            &self.pool,
            event_id,
            completed_at,
            "material_cleanup_completed_at",
        )
        .await
    }

    async fn complete_mls_obligation(
        &self,
        event_id: &arkret_wire::EventId,
        completed_at: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<bool> {
        complete(
            &self.pool,
            event_id,
            completed_at,
            "mls_obligation_completed_at",
        )
        .await
    }
}

#[derive(QueryableByName)]
struct SequenceRow {
    #[diesel(sql_type = BigInt)]
    linearization_seq: i64,
}

async fn complete(
    pool: &PgPool,
    event_id: &arkret_wire::EventId,
    completed_at: chrono::DateTime<chrono::Utc>,
    column: &str,
) -> PersistenceResult<bool> {
    debug_assert!(matches!(
        column,
        "material_cleanup_completed_at" | "mls_obligation_completed_at"
    ));
    let mut conn = crate::pg_db(pool);
    sql_query(format!(
        "UPDATE device_revocation_cleanup_intents SET {column}=COALESCE({column},$2) \
         WHERE event_id=$1 AND {column} IS NULL"
    ))
    .bind::<Text, _>(event_id.as_str())
    .bind::<Timestamptz, _>(completed_at)
    .execute(&mut conn)
    .await
    .map(|rows| rows == 1)
    .map_err(PersistenceError::database)
}

#[derive(QueryableByName)]
struct CurrentDeviceCommitRow {
    #[diesel(sql_type = Jsonb)]
    stream_ref: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
}

#[derive(QueryableByName)]
struct LocalStationRow {
    #[diesel(sql_type = Text)]
    station_id: arkret_wire::DidCoreId,
}

/// Lock every device instance touched by one private-artifact transaction in a
/// deterministic order. The authorization reference is part of the lock key,
/// so a rotated instance cannot alias its predecessor.
pub(crate) async fn lock_artifact_devices_in_transaction(
    conn: &mut AsyncPgConnection,
    selectors: &[&DeviceRevocationGateSelector],
) -> PersistenceResult<()> {
    let mut keys = selectors
        .iter()
        .map(|selector| {
            format!(
                "{}\u{1f}{}\u{1f}{}\u{1f}{}",
                selector.principal_id,
                selector.station_id,
                selector.device_id,
                selector.authorization_ref.event_id
            )
        })
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    for key in keys {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind::<Text, _>(key)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    }
    Ok(())
}

pub(crate) async fn current_device_binding_in_transaction(
    conn: &mut AsyncPgConnection,
    principal_id: &arkret_wire::DidCoreId,
    station_id: &arkret_wire::DidCoreId,
    device_id: &str,
) -> PersistenceResult<Option<DeviceRevocationGateSelector>> {
    let account = arkret_wire::AccountId::new(principal_id.clone(), station_id.clone());
    let device =
        arkret_wire::DeviceId::new(device_id.to_owned()).map_err(PersistenceError::database)?;
    let Some(cut) = crate::pcr_device_revocation_proposals::confirmed_pcr_device_cut_in_connection(
        conn, &account, &device,
    )
    .await?
    else {
        return Ok(None);
    };
    let Some(authorization) = cut.authorization.filter(|authorization| {
        Some(authorization.payload.authorized_generation_ref) == cut.current_generation
    }) else {
        return Ok(None);
    };
    let row = sql_query(
        "SELECT c.stream_ref, c.stream_position FROM realm_commits c \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.commit_id=$1 AND c.realm_id=$2 AND e.envelope->>'event_id'=$3",
    )
    .bind::<Text, _>(authorization.source_commit_id.as_str())
    .bind::<Text, _>(cut.realm_id.as_str())
    .bind::<Text, _>(authorization.event_id.as_str())
    .get_result::<CurrentDeviceCommitRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| {
        PersistenceError::SchemaViolation(
            "PCR device authorization has no exact covering Commit".to_owned(),
        )
    })?;
    Ok(Some(DeviceRevocationGateSelector {
        principal_id: principal_id.clone(),
        station_id: station_id.clone(),
        device_id: device_id.to_owned(),
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: authorization.event_id,
            commit_id: authorization.source_commit_id,
            stream_ref: serde_json::from_value(row.stream_ref)
                .map_err(PersistenceError::database)?,
            stream_position: u64::try_from(row.stream_position)
                .map_err(PersistenceError::database)?,
        },
    }))
}

pub(crate) async fn local_device_binding_in_transaction(
    conn: &mut AsyncPgConnection,
    principal: &str,
    device_id: &str,
) -> PersistenceResult<Option<DeviceRevocationGateSelector>> {
    let station = sql_query("SELECT station_id FROM device_inventory_station WHERE singleton")
        .get_result::<LocalStationRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
    let Some(station) = station else {
        return Ok(None);
    };
    let principal = arkret_wire::DidCoreId::new(principal.to_owned())
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    current_device_binding_in_transaction(conn, &principal, &station.station_id, device_id).await
}

/// Record one accepted device revocation on a caller-owned connection.
///
/// The revocation target and its cleanup intent belong to the same durable
/// boundary as the `ak.device.revoke` Event that authorized them, so the Event
/// commit unit of work calls this inside its single transaction.
pub(crate) async fn commit_revocation_in_connection(
    conn: &mut AsyncPgConnection,
    transition: &DeviceRevocationTransition,
) -> Result<DeviceRevocationTransitionDecision, PgTransactionError> {
    lock_artifact_devices_in_transaction(conn, &[&transition.selector]).await?;
    let event_id = transition.revoke_ref.event_id.as_str();
    let existing = sql_query(
        "SELECT selector, committed_ref, committed_at FROM device_revocation_targets \
         WHERE event_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(event_id)
    .get_result::<TargetRow>(&mut *conn)
    .await
    .optional()?
    .map(target)
    .transpose()?;
    let decision = classify_device_revocation_transition(transition, existing.as_ref())?;
    if decision == DeviceRevocationTransitionDecision::Insert {
        let selector =
            serde_json::to_value(&transition.selector).map_err(PersistenceError::database)?;
        let committed_ref =
            serde_json::to_value(&transition.revoke_ref).map_err(PersistenceError::database)?;
        sql_query(
            "INSERT INTO device_revocation_targets \
             (event_id,selector,committed_ref,committed_at) VALUES ($1,$2,$3,$4)",
        )
        .bind::<Text, _>(event_id)
        .bind::<Jsonb, _>(&selector)
        .bind::<Jsonb, _>(&committed_ref)
        .bind::<Timestamptz, _>(transition.committed_at)
        .execute(&mut *conn)
        .await?;
        sql_query(
            "INSERT INTO device_revocation_cleanup_intents \
             (event_id,committed_ref,selector,created_at) VALUES ($1,$2,$3,$4)",
        )
        .bind::<Text, _>(event_id)
        .bind::<Jsonb, _>(&committed_ref)
        .bind::<Jsonb, _>(&selector)
        .bind::<Timestamptz, _>(transition.committed_at)
        .execute(&mut *conn)
        .await?;
    }
    crate::push_handoff::revoke_public_push_routes_for_device_in_connection(conn, transition)
        .await?;
    Ok(decision)
}
pub(crate) async fn gate_status_in_transaction(
    conn: &mut AsyncPgConnection,
    selector: &DeviceRevocationGateSelector,
) -> PersistenceResult<DeviceRevocationGateStatus> {
    let selector_json = serde_json::to_value(selector).map_err(PersistenceError::database)?;
    if let Some(row) = sql_query(
        "SELECT selector, committed_ref, committed_at FROM device_revocation_targets \
         WHERE selector=$1 ORDER BY committed_at DESC LIMIT 1",
    )
    .bind::<Jsonb, _>(selector_json)
    .get_result::<TargetRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    {
        let record = target(row)?;
        return Ok(DeviceRevocationGateStatus::Revoked {
            revoke_ref: record.revoke_ref,
            committed_at: record.committed_at,
        });
    }
    let Some(current) = current_device_binding_in_transaction(
        conn,
        &selector.principal_id,
        &selector.station_id,
        &selector.device_id,
    )
    .await?
    else {
        return Ok(DeviceRevocationGateStatus::AuthorityMismatch);
    };
    if current.authorization_ref != selector.authorization_ref {
        return Ok(DeviceRevocationGateStatus::GenerationMismatch);
    }
    if current != *selector {
        return Ok(DeviceRevocationGateStatus::AuthorityMismatch);
    }
    Ok(DeviceRevocationGateStatus::Active)
}

pub(crate) async fn ensure_gate_allowed_in_transaction(
    conn: &mut AsyncPgConnection,
    selector: &DeviceRevocationGateSelector,
) -> PersistenceResult<()> {
    gate_status_in_transaction(conn, selector)
        .await?
        .ensure_allowed()
}

/// Reject an exact device generation once its accepted revocation target is
/// durable, without requiring the caller to own the current-device inventory
/// validation performed by the later material commit UOW.
pub(crate) async fn ensure_gate_not_revoked_in_transaction(
    conn: &mut AsyncPgConnection,
    selector: &DeviceRevocationGateSelector,
) -> PersistenceResult<()> {
    let selector_json = serde_json::to_value(selector).map_err(PersistenceError::database)?;
    let revoked = sql_query(
        "SELECT selector, committed_ref, committed_at FROM device_revocation_targets \
         WHERE selector=$1 ORDER BY committed_at DESC LIMIT 1",
    )
    .bind::<Jsonb, _>(selector_json)
    .get_result::<TargetRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .is_some();
    if revoked {
        return Err(PersistenceError::Conflict(
            "failed_precondition: device authorization has been revoked".to_owned(),
        ));
    }
    Ok(())
}
