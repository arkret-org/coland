use arkret_models_integration::{
    PushRegistrationHandoffRequestBody, PushRegistrationId, PushRegistrationInstallationReceipt,
    PushRegistrationRecord,
};
use arkret_wire::{AccountId, DeviceId, DidCoreId, Hash};

use super::{
    AsyncConnection, AsyncPgConnection, BigInt, Binary, Jsonb, Nullable, OptionalExtension,
    PersistenceError, PersistenceResult, PgPool, PgTransactionError, PushHardLogoutJournalRecord,
    PushRegistrationHandoffExpiryCursor, PushRegistrationHandoffExpiryPage,
    PushRegistrationHandoffIntentRecord, PushRegistrationHandoffIntentStatus,
    PushRegistrationHandoffIntentWrite, PushRegistrationHandoffReceiptWrite,
    PushRegistrationHandoffRetryCursor, PushRegistrationHandoffRouteLocator,
    PushRegistrationHandoffStore, QueryableByName, RunQueryDsl, Text, Timestamptz, Value,
    apply_push_registration_desired_intent, apply_verified_push_registration_receipt, async_trait,
    pg_conn, sql_query,
};
use crate::push::{
    PushDeviceRouteWriteMode, push_device_lock_key, write_push_device_route_in_transaction,
};

pub struct PgPushRegistrationHandoffStore {
    pub pool: PgPool,
}

#[derive(QueryableByName)]
struct CurrentPushRouteRow {
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Jsonb)]
    device_authorization: Value,
    #[diesel(sql_type = super::Bool)]
    public_handoff: bool,
}

#[derive(QueryableByName)]
struct HandoffIntentRow {
    #[diesel(sql_type = Text)]
    source_station_id: DidCoreId,
    #[diesel(sql_type = Jsonb)]
    local_account_id: Value,
    #[diesel(sql_type = Text)]
    local_device_id: String,
    #[diesel(sql_type = Text)]
    local_push_route_id: String,
    #[diesel(sql_type = Jsonb)]
    device_authorization: Value,
    #[diesel(sql_type = Text)]
    registration_id: String,
    #[diesel(sql_type = Text)]
    destination_gateway_id: DidCoreId,
    #[diesel(sql_type = Text)]
    desired_state: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Text)]
    client_input_digest: String,
    #[diesel(sql_type = Binary)]
    canonical_request: Vec<u8>,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = Nullable<Jsonb>)]
    receipt: Option<Value>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Timestamptz)]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<HandoffIntentRow> for PushRegistrationHandoffIntentRecord {
    type Error = PersistenceError;

    fn try_from(row: HandoffIntentRow) -> Result<Self, Self::Error> {
        let local_route = PushRegistrationHandoffRouteLocator {
            account_id: serde_json::from_value(row.local_account_id).map_err(|error| {
                PersistenceError::Internal(format!(
                    "stored push registration handoff local account is invalid: {error}"
                ))
            })?,
            device_id: arkret_wire::DeviceId::new(row.local_device_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            push_route_id: row.local_push_route_id,
            destination_gateway_id: row.destination_gateway_id.clone(),
        };
        let record = Self {
            source_station_id: row.source_station_id,
            local_route,
            device_authorization: serde_json::from_value(row.device_authorization).map_err(
                |error| {
                    PersistenceError::Internal(format!(
                        "stored push handoff device authorization is invalid: {error}"
                    ))
                },
            )?,
            client_input_digest: Hash::new(row.client_input_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            destination_gateway_id: row.destination_gateway_id,
            registration_id: PushRegistrationId::new(row.registration_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            desired_state: serde_json::from_value(Value::String(row.desired_state)).map_err(
                |error| {
                    PersistenceError::Internal(format!(
                        "stored push registration handoff desired state is invalid: {error}"
                    ))
                },
            )?,
            request_digest: Hash::new(row.request_digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            canonical_request: row.canonical_request,
            status: match row.status.as_str() {
                "awaiting_receipt" => PushRegistrationHandoffIntentStatus::AwaitingReceipt,
                "receipt_verified" => PushRegistrationHandoffIntentStatus::ReceiptVerified,
                _ => {
                    return Err(PersistenceError::Internal(format!(
                        "stored push registration handoff status is invalid: {}",
                        row.status
                    )));
                }
            },
            receipt: row
                .receipt
                .map(serde_json::from_value)
                .transpose()
                .map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored push registration handoff receipt is invalid: {error}"
                    ))
                })?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        };
        record.validate()?;
        Ok(record)
    }
}

const HANDOFF_COLUMNS: &str = "source_station_id, local_account_id, local_device_id, \
    local_push_route_id, device_authorization, registration_id, destination_gateway_id, \
    desired_state, request_digest, client_input_digest, canonical_request, status, receipt, \
    created_at, updated_at";

#[derive(QueryableByName)]
struct AccountLifecycleStateRow {
    #[diesel(sql_type = Text)]
    state: String,
}

#[derive(QueryableByName)]
struct PublicHandoffDeviceRow {
    #[diesel(sql_type = Text)]
    device_id: String,
}

#[derive(QueryableByName)]
struct HardLogoutJournalRow {
    #[diesel(sql_type = Text)]
    grant_token_digest: String,
    #[diesel(sql_type = Text)]
    revocation_ref: String,
    #[diesel(sql_type = Jsonb)]
    account_id: Value,
    #[diesel(sql_type = Text)]
    device_id: String,
    #[diesel(sql_type = Text)]
    cnf_jkt: String,
    #[diesel(sql_type = super::Bool)]
    auth_side_confirmed: bool,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[diesel(sql_type = Timestamptz)]
    created_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<HardLogoutJournalRow> for PushHardLogoutJournalRecord {
    type Error = PersistenceError;

    fn try_from(row: HardLogoutJournalRow) -> Result<Self, Self::Error> {
        Ok(Self {
            grant_token_digest: row.grant_token_digest,
            revocation_ref: row.revocation_ref,
            account_id: serde_json::from_value(row.account_id)
                .map_err(PersistenceError::database)?,
            device_id: DeviceId::new(row.device_id)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
            cnf_jkt: row.cnf_jkt,
            auth_side_confirmed: row.auth_side_confirmed,
            completed_at: row.completed_at,
            created_at: row.created_at,
        })
    }
}

const HARD_LOGOUT_COLUMNS: &str = "grant_token_digest, revocation_ref, account_id, \
    device_id, cnf_jkt, auth_side_confirmed, completed_at, created_at";

fn logout_family_lock_key(revocation_ref: &str) -> String {
    format!("push-hard-logout:{revocation_ref}")
}

async fn lock_logout_family(
    conn: &mut AsyncPgConnection,
    revocation_ref: &str,
) -> PersistenceResult<()> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(logout_family_lock_key(revocation_ref))
        .execute(conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}

async fn ensure_logout_family_not_fenced(
    conn: &mut AsyncPgConnection,
    revocation_ref: &str,
) -> PersistenceResult<()> {
    lock_logout_family(conn, revocation_ref).await?;
    #[derive(QueryableByName)]
    struct FenceRow {
        #[diesel(sql_type = super::Bool)]
        fenced: bool,
    }
    let row = sql_query(
        "SELECT EXISTS (SELECT 1 FROM push_hard_logout_journal \
         WHERE revocation_ref = $1) AS fenced",
    )
    .bind::<Text, _>(revocation_ref)
    .get_result::<FenceRow>(conn)
    .await
    .map_err(PersistenceError::database)?;
    if row.fenced {
        return Err(PersistenceError::Conflict(
            "cas_conflict: public push handoff grant family has logged out".to_owned(),
        ));
    }
    Ok(())
}

/// Serialize active public handoff writes with account lifecycle changes.
/// The lifecycle writer locks the same account row before changing its state.
pub(crate) async fn ensure_active_account_in_transaction(
    conn: &mut AsyncPgConnection,
    account_id: &AccountId,
) -> PersistenceResult<()> {
    let account = sql_query(
        "SELECT 'active' AS state FROM accounts a \
         WHERE a.principal_id = $1 AND a.station_id = $2 FOR SHARE OF a",
    )
    .bind::<Text, _>(&account_id.principal_id)
    .bind::<Text, _>(&account_id.station_id)
    .get_result::<AccountLifecycleStateRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if account.is_none() {
        return Err(PersistenceError::Conflict(
            "cas_conflict: public push handoff requires an active account".to_owned(),
        ));
    }
    // This separate statement must run after the account row lock is acquired,
    // so READ COMMITTED observes a lifecycle update that just released it.
    let lifecycle = sql_query(
        "SELECT l.state FROM account_lifecycle l JOIN accounts a ON a.pk = l.account_pk \
         WHERE a.principal_id = $1 AND a.station_id = $2",
    )
    .bind::<Text, _>(&account_id.principal_id)
    .bind::<Text, _>(&account_id.station_id)
    .get_result::<AccountLifecycleStateRow>(conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if lifecycle.is_some_and(|lifecycle| lifecycle.state != "active") {
        return Err(PersistenceError::Conflict(
            "cas_conflict: public push handoff requires an active account".to_owned(),
        ));
    }
    Ok(())
}

async fn load_intent(
    conn: &mut AsyncPgConnection,
    source_station_id: &DidCoreId,
    registration_id: &PushRegistrationId,
    for_update: bool,
) -> PersistenceResult<Option<PushRegistrationHandoffIntentRecord>> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    let query = format!(
        "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
         WHERE source_station_id = $1 AND registration_id = $2{suffix}"
    );
    sql_query(query)
        .bind::<Text, _>(source_station_id)
        .bind::<Text, _>(registration_id.as_str())
        .get_result::<HandoffIntentRow>(conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(TryInto::try_into)
        .transpose()
}

async fn load_local_route_intent(
    conn: &mut AsyncPgConnection,
    source_station_id: &DidCoreId,
    local_route: &PushRegistrationHandoffRouteLocator,
    for_update: bool,
) -> PersistenceResult<Option<PushRegistrationHandoffIntentRecord>> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    let account_id =
        serde_json::to_value(&local_route.account_id).map_err(PersistenceError::database)?;
    let query = format!(
        "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
         WHERE source_station_id = $1 AND local_account_id = $2 \
           AND local_device_id = $3 AND local_push_route_id = $4 \
           AND destination_gateway_id = $5 \
         ORDER BY (status = 'awaiting_receipt') DESC, updated_at DESC, registration_id DESC \
         LIMIT 1{suffix}"
    );
    sql_query(query)
        .bind::<Text, _>(source_station_id)
        .bind::<Jsonb, _>(&account_id)
        .bind::<Text, _>(local_route.device_id.as_str())
        .bind::<Text, _>(&local_route.push_route_id)
        .bind::<Text, _>(&local_route.destination_gateway_id)
        .get_result::<HandoffIntentRow>(conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .map(TryInto::try_into)
        .transpose()
}

fn local_route_lock_key(
    source_station_id: &DidCoreId,
    local_route: &PushRegistrationHandoffRouteLocator,
) -> PersistenceResult<String> {
    let canonical = arkret_canonical::canonical::canonical_json_bytes(&serde_json::json!({
        "source_station_id": source_station_id,
        "local_route": local_route,
    }))
    .map_err(PersistenceError::database)?;
    Ok(format!(
        "push-registration-handoff:{}",
        arkret_canonical::sha256_hex(canonical)
    ))
}

async fn store_receipt_transition(
    conn: &mut AsyncPgConnection,
    source_station_id: &DidCoreId,
    registration_id: &PushRegistrationId,
    expected_request_digest: &Hash,
    outcome: &PushRegistrationHandoffReceiptWrite,
) -> PersistenceResult<()> {
    let PushRegistrationHandoffReceiptWrite::Stored(committed) = outcome else {
        return Ok(());
    };
    let receipt_json = serde_json::to_value(
        committed
            .receipt
            .as_ref()
            .expect("stored receipt transition carries a receipt"),
    )
    .map_err(PersistenceError::database)?;
    let updated = sql_query(
        "UPDATE push_registration_handoff_intents \
         SET status = $4, receipt = $5, updated_at = $6 \
         WHERE source_station_id = $1 AND registration_id = $2 \
           AND request_digest = $3 AND status = 'awaiting_receipt' AND receipt IS NULL",
    )
    .bind::<Text, _>(source_station_id)
    .bind::<Text, _>(registration_id.as_str())
    .bind::<Text, _>(expected_request_digest.as_str())
    .bind::<Text, _>(committed.status.as_str())
    .bind::<Jsonb, _>(&receipt_json)
    .bind::<Timestamptz, _>(committed.updated_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if updated != 1 {
        return Err(PersistenceError::Conflict(
            "cas_conflict: push registration handoff receipt state changed".to_owned(),
        ));
    }
    Ok(())
}

fn active_request_matches_filters(
    request: &PushRegistrationHandoffRequestBody,
    push_key: Option<&str>,
    app_id: Option<&str>,
) -> bool {
    let PushRegistrationHandoffRequestBody::Active {
        push_key: request_push_key,
        app_id: request_app_id,
        ..
    } = request
    else {
        return false;
    };
    push_key.is_none_or(|expected| expected == request_push_key.as_str())
        && app_id.is_none_or(|expected| Some(expected) == request_app_id.as_deref())
}

fn public_unregistration_input_digest(
    account_id: &AccountId,
    device_id: &DeviceId,
    push_key: Option<&str>,
    app_id: Option<&str>,
) -> PersistenceResult<Hash> {
    let input = serde_json::json!({
        "account_id": account_id,
        "device_id": device_id,
        "push_key": push_key,
        "app_id": app_id,
    });
    Hash::new(arkret_canonical::canonical_sha256(&input).map_err(PersistenceError::database)?)
        .map_err(|error| PersistenceError::Internal(error.to_string()))
}

async fn advance_active_intent_to_revoked(
    conn: &mut AsyncPgConnection,
    stored: &PushRegistrationHandoffIntentRecord,
    client_input_digest: &Hash,
    now: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<PushRegistrationHandoffIntentRecord> {
    let active = stored.request()?;
    let PushRegistrationHandoffRequestBody::Active {
        push_target_id,
        device_id,
        ..
    } = active
    else {
        return Err(PersistenceError::Conflict(
            "cas_conflict: public push handoff is not active".to_owned(),
        ));
    };
    let revoke_request = PushRegistrationHandoffRequestBody::Revoked {
        registration_id: stored.registration_id.clone(),
        push_target_id,
        device_id,
    };
    let candidate = PushRegistrationHandoffIntentRecord::prepare(
        stored.source_station_id.clone(),
        stored.local_route.clone(),
        stored.device_authorization.clone(),
        client_input_digest.clone(),
        &revoke_request,
        now,
    )?;
    let outcome = apply_push_registration_desired_intent(stored, &candidate)?;
    let PushRegistrationHandoffIntentWrite::AdvancedToRevoked(revoked) = outcome else {
        return Err(PersistenceError::Conflict(
            "cas_conflict: public push handoff did not advance to revoked".to_owned(),
        ));
    };
    let updated = sql_query(
        "UPDATE push_registration_handoff_intents \
         SET desired_state = $5, request_digest = $6, client_input_digest = $7, \
             canonical_request = $8, status = $9, receipt = NULL, updated_at = $10 \
         WHERE source_station_id = $1 AND registration_id = $2 \
           AND destination_gateway_id = $3 AND request_digest = $4 \
           AND desired_state = 'active'",
    )
    .bind::<Text, _>(&stored.source_station_id)
    .bind::<Text, _>(stored.registration_id.as_str())
    .bind::<Text, _>(&stored.destination_gateway_id)
    .bind::<Text, _>(stored.request_digest.as_str())
    .bind::<Text, _>(revoked.desired_state.as_str())
    .bind::<Text, _>(revoked.request_digest.as_str())
    .bind::<Text, _>(revoked.client_input_digest.as_str())
    .bind::<Binary, _>(&revoked.canonical_request)
    .bind::<Text, _>(revoked.status.as_str())
    .bind::<Timestamptz, _>(revoked.updated_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if updated != 1 {
        return Err(PersistenceError::Conflict(
            "cas_conflict: public push handoff changed during unregistration".to_owned(),
        ));
    }
    Ok(revoked)
}

fn device_revocation_input_digest(
    transition: &coland_storage::DeviceRevocationTransition,
) -> PersistenceResult<Hash> {
    let input = serde_json::json!({
        "operation": "ak.device.revoke.public_push",
        "selector": transition.selector,
        "revoke_ref": transition.revoke_ref,
    });
    Hash::new(arkret_canonical::canonical_sha256(&input).map_err(PersistenceError::database)?)
        .map_err(|error| PersistenceError::Internal(error.to_string()))
}

fn expiry_input_digest(
    stored: &PushRegistrationHandoffIntentRecord,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Hash> {
    let input = serde_json::json!({
        "operation": "ak.push.registration.expiry",
        "source_station_id": stored.source_station_id,
        "registration_id": stored.registration_id,
        "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
    });
    Hash::new(arkret_canonical::canonical_sha256(&input).map_err(PersistenceError::database)?)
        .map_err(|error| PersistenceError::Internal(error.to_string()))
}

async fn expire_public_push_registration(
    pool: &PgPool,
    source_station_id: &DidCoreId,
    snapshot: &PushRegistrationHandoffIntentRecord,
    now: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<PushRegistrationHandoffIntentRecord>> {
    let source_station_id = source_station_id.clone();
    let snapshot = snapshot.clone();
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        crate::device_revocations::lock_artifact_devices_in_transaction(
            conn,
            &[&snapshot.device_authorization],
        )
        .await?;
        let account_lock_key = push_device_lock_key(
            &snapshot.local_route.account_id,
            snapshot.local_route.device_id.as_str(),
        );
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind::<Text, _>(&account_lock_key)
            .execute(&mut *conn)
            .await?;
        let route_lock_key = local_route_lock_key(&source_station_id, &snapshot.local_route)?;
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind::<Text, _>(&route_lock_key)
            .execute(&mut *conn)
            .await?;

        let stored = load_intent(conn, &source_station_id, &snapshot.registration_id, true)
            .await?
            .ok_or_else(|| {
                PersistenceError::Conflict(
                    "cas_conflict: expiring public push handoff disappeared".to_owned(),
                )
            })?;
        if stored.desired_state == arkret_models_integration::PushRegistrationHandoffState::Revoked
        {
            return Ok(None);
        }
        if stored.request_digest != snapshot.request_digest
            || stored.device_authorization != snapshot.device_authorization
            || stored.local_route != snapshot.local_route
        {
            return Err(PersistenceError::Conflict(
                "cas_conflict: public push handoff changed during expiry".to_owned(),
            )
            .into());
        }
        let request = stored.request()?;
        let PushRegistrationHandoffRequestBody::Active {
            expires_at: Some(expires_at),
            ..
        } = request
        else {
            return Err(PersistenceError::Conflict(
                "cas_conflict: selected public push handoff has no expiry".to_owned(),
            )
            .into());
        };
        if expires_at > now {
            return Err(PersistenceError::Conflict(
                "cas_conflict: public push handoff is not expired".to_owned(),
            )
            .into());
        }

        let route = sql_query(
            "SELECT payload,device_authorization,public_handoff FROM push_devices \
             WHERE id=$1 FOR UPDATE",
        )
        .bind::<Text, _>(stored.registration_id.as_str())
        .get_result::<CurrentPushRouteRow>(&mut *conn)
        .await
        .optional()?;
        if let Some(route) = route {
            if !route.public_handoff {
                return Err(PersistenceError::Conflict(
                    "cas_conflict: expiring handoff collides with a local-only route".to_owned(),
                )
                .into());
            }
            let route_authorization: coland_storage::DeviceRevocationGateSelector =
                serde_json::from_value(route.device_authorization.clone()).map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored public push route authorization is invalid during expiry: {error}"
                    ))
                })?;
            if route_authorization != stored.device_authorization {
                return Err(PersistenceError::Conflict(
                    "cas_conflict: public push route authorization changed during expiry"
                        .to_owned(),
                )
                .into());
            }
            let registration: PushRegistrationRecord = serde_json::from_value(route.payload)
                .map_err(|error| {
                    PersistenceError::Internal(format!(
                        "stored push route is invalid during expiry: {error}"
                    ))
                })?;
            let mut installation = registration.clone();
            installation.retained_push_targets.clear();
            stored
                .validate_active_local_registration(&stored.device_authorization, &installation)?;
            let removed = sql_query(
                "DELETE FROM push_devices WHERE id=$1 AND public_handoff=TRUE \
                   AND device_authorization=$2",
            )
            .bind::<Text, _>(stored.registration_id.as_str())
            .bind::<Jsonb, _>(&route.device_authorization)
            .execute(&mut *conn)
            .await?;
            if removed != 1 {
                return Err(PersistenceError::Conflict(
                    "cas_conflict: public push route changed during expiry".to_owned(),
                )
                .into());
            }
        }
        let digest = expiry_input_digest(&stored, expires_at)?;
        Ok(Some(
            advance_active_intent_to_revoked(conn, &stored, &digest, now).await?,
        ))
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

/// Turn every public Gateway route owned by one exact device generation into
/// a durable revoke before removing its locally deliverable route.
///
/// The caller holds the exact device-generation advisory lock and owns the
/// surrounding transaction. That makes this operation atomic with the
/// accepted `ak.device.revoke` Event and excludes a concurrent active intent
/// or receipt commit from appearing between the scan and the tombstone write.
pub(crate) async fn revoke_public_push_routes_for_device_in_connection(
    conn: &mut AsyncPgConnection,
    transition: &coland_storage::DeviceRevocationTransition,
) -> PersistenceResult<usize> {
    let selector_json =
        serde_json::to_value(&transition.selector).map_err(PersistenceError::database)?;
    let account_id = AccountId::new(
        transition.selector.principal_id.clone(),
        transition.selector.station_id.clone(),
    );
    let account_json = serde_json::to_value(&account_id).map_err(PersistenceError::database)?;
    let query = format!(
        "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
         WHERE device_authorization = $1 \
         ORDER BY source_station_id, local_push_route_id, destination_gateway_id, registration_id"
    );
    let snapshots = sql_query(query)
        .bind::<Jsonb, _>(&selector_json)
        .load::<HandoffIntentRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(TryInto::try_into)
        .collect::<PersistenceResult<Vec<PushRegistrationHandoffIntentRecord>>>()?;

    for snapshot in &snapshots {
        if snapshot.source_station_id != transition.selector.station_id
            || snapshot.local_route.account_id != account_id
            || snapshot.local_route.device_id.as_str() != transition.selector.device_id
        {
            return Err(PersistenceError::Conflict(
                "cas_conflict: public push handoff differs from revoked device generation"
                    .to_owned(),
            ));
        }
    }

    let account_lock_key = push_device_lock_key(&account_id, &transition.selector.device_id);
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(&account_lock_key)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let mut route_lock_keys = snapshots
        .iter()
        .map(|snapshot| local_route_lock_key(&snapshot.source_station_id, &snapshot.local_route))
        .collect::<PersistenceResult<Vec<_>>>()?;
    route_lock_keys.sort();
    route_lock_keys.dedup();
    for route_lock_key in route_lock_keys {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind::<Text, _>(&route_lock_key)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    }

    let mut handoffs = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots {
        let stored = load_intent(
            conn,
            &snapshot.source_station_id,
            &snapshot.registration_id,
            true,
        )
        .await?
        .ok_or_else(|| {
            PersistenceError::Conflict(
                "cas_conflict: public push handoff disappeared during device revocation".to_owned(),
            )
        })?;
        if stored.device_authorization != transition.selector
            || stored.request_digest != snapshot.request_digest
        {
            return Err(PersistenceError::Conflict(
                "cas_conflict: public push handoff changed during device revocation".to_owned(),
            ));
        }
        handoffs.push(stored);
    }

    let routes = sql_query(
        "SELECT payload, device_authorization, public_handoff FROM push_devices \
         WHERE device_authorization = $1 ORDER BY payload->>'push_route_id', id FOR UPDATE",
    )
    .bind::<Jsonb, _>(&selector_json)
    .load::<CurrentPushRouteRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut public_routes = Vec::new();
    for route in routes {
        let registration: PushRegistrationRecord = serde_json::from_value(route.payload.clone())
            .map_err(|error| {
                PersistenceError::Internal(format!(
                    "stored push route is invalid during device revocation: {error}"
                ))
            })?;
        if !route.public_handoff {
            continue;
        }
        let stored = handoffs
            .iter()
            .find(|record| record.registration_id.as_str() == registration.registration_id.as_str())
            .ok_or_else(|| {
                PersistenceError::Conflict(
                    "cas_conflict: public push route has no durable handoff".to_owned(),
                )
            })?;
        if stored.desired_state != arkret_models_integration::PushRegistrationHandoffState::Active
            || stored.status != PushRegistrationHandoffIntentStatus::ReceiptVerified
        {
            return Err(PersistenceError::Conflict(
                "cas_conflict: public push route has no verified handoff receipt".to_owned(),
            ));
        }
        // Retained predecessors are Station-local delivery state and are not
        // part of the Gateway installation binding. Validate every wire-bound
        // field against a normalized view while deleting the exact stored row.
        let mut installation = registration.clone();
        installation.retained_push_targets.clear();
        stored.validate_active_local_registration(&transition.selector, &installation)?;
        public_routes.push((registration, route.device_authorization));
    }

    let revoke_input_digest = device_revocation_input_digest(transition)?;
    for stored in handoffs.iter().filter(|record| {
        record.desired_state == arkret_models_integration::PushRegistrationHandoffState::Active
    }) {
        advance_active_intent_to_revoked(
            conn,
            stored,
            &revoke_input_digest,
            transition.committed_at,
        )
        .await?;
    }
    for (registration, authorization) in &public_routes {
        let removed = sql_query(
            "DELETE FROM push_devices WHERE payload->'account_id' = $1 \
               AND device_id = $2 AND payload->>'push_route_id' = $3 \
               AND id = $4 AND device_authorization = $5",
        )
        .bind::<Jsonb, _>(&account_json)
        .bind::<Text, _>(&transition.selector.device_id)
        .bind::<Text, _>(&registration.push_route_id)
        .bind::<Text, _>(registration.registration_id.as_str())
        .bind::<Jsonb, _>(authorization)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        if removed != 1 {
            return Err(PersistenceError::Conflict(
                "cas_conflict: public push route changed during device revocation".to_owned(),
            ));
        }
    }
    Ok(public_routes.len())
}

#[async_trait]
impl PushRegistrationHandoffStore for PgPushRegistrationHandoffStore {
    async fn reserve_hard_logout_journal(
        &self,
        record: &PushHardLogoutJournalRecord,
    ) -> PersistenceResult<PushHardLogoutJournalRecord> {
        record
            .account_id
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if !record
            .revocation_ref
            .starts_with("org.arkret.coauth.browser_session:")
            || record.revocation_ref == "org.arkret.coauth.browser_session:"
            || record.grant_token_digest.is_empty()
            || record.cnf_jkt.is_empty()
            || record.auth_side_confirmed
            || record.completed_at.is_some()
        {
            return Err(PersistenceError::SchemaViolation(
                "invalid standard human hard logout journal reservation".to_owned(),
            ));
        }
        let record = record.clone();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            lock_logout_family(conn, &record.revocation_ref).await?;
            let query = format!(
                "SELECT {HARD_LOGOUT_COLUMNS} FROM push_hard_logout_journal \
                 WHERE grant_token_digest = $1 FOR UPDATE"
            );
            let existing = sql_query(query)
                .bind::<Text, _>(&record.grant_token_digest)
                .get_result::<HardLogoutJournalRow>(conn)
                .await
                .optional()?;
            if let Some(existing) = existing {
                let existing: PushHardLogoutJournalRecord = existing.try_into()?;
                if existing.revocation_ref != record.revocation_ref
                    || existing.account_id != record.account_id
                    || existing.device_id != record.device_id
                    || existing.cnf_jkt != record.cnf_jkt
                {
                    return Err(PersistenceError::Conflict(
                        "cas_conflict: hard logout journal binding changed".to_owned(),
                    )
                    .into());
                }
                return Ok(existing);
            }
            let account_json =
                serde_json::to_value(&record.account_id).map_err(PersistenceError::database)?;
            #[derive(QueryableByName)]
            struct FamilyBindingRow {
                #[diesel(sql_type = super::Jsonb)]
                account_id: serde_json::Value,
                #[diesel(sql_type = super::Text)]
                device_id: String,
            }
            let existing_family = sql_query(
                "SELECT account_id, device_id FROM push_hard_logout_journal \
                 WHERE revocation_ref = $1 LIMIT 1 FOR UPDATE",
            )
            .bind::<Text, _>(&record.revocation_ref)
            .get_result::<FamilyBindingRow>(conn)
            .await
            .optional()?;
            if let Some(existing_family) = existing_family
                && (existing_family.account_id != account_json
                    || existing_family.device_id != record.device_id.as_str())
            {
                return Err(PersistenceError::Conflict(
                    "cas_conflict: hard logout family account or device changed".to_owned(),
                )
                .into());
            }
            sql_query(
                "INSERT INTO push_hard_logout_journal \
                 (grant_token_digest, revocation_ref, account_id, device_id, cnf_jkt, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind::<Text, _>(&record.grant_token_digest)
            .bind::<Text, _>(&record.revocation_ref)
            .bind::<Jsonb, _>(account_json)
            .bind::<Text, _>(record.device_id.as_str())
            .bind::<Text, _>(&record.cnf_jkt)
            .bind::<Timestamptz, _>(record.created_at)
            .execute(conn)
            .await?;
            Ok(record)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn hard_logout_journal(
        &self,
        grant_token_digest: &str,
    ) -> PersistenceResult<Option<PushHardLogoutJournalRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        let query = format!(
            "SELECT {HARD_LOGOUT_COLUMNS} FROM push_hard_logout_journal \
             WHERE grant_token_digest = $1"
        );
        sql_query(query)
            .bind::<Text, _>(grant_token_digest)
            .get_result::<HardLogoutJournalRow>(&mut conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .map(TryInto::try_into)
            .transpose()
    }

    async fn pending_confirmed_hard_logouts(
        &self,
        after_digest: Option<&str>,
        limit: usize,
    ) -> PersistenceResult<Vec<PushHardLogoutJournalRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut conn = pg_conn(&self.pool).await?;
        let limit = i64::try_from(limit.min(1_000)).map_err(PersistenceError::database)?;
        let query = format!(
            "SELECT {HARD_LOGOUT_COLUMNS} FROM push_hard_logout_journal \
             WHERE auth_side_confirmed = TRUE AND completed_at IS NULL \
               AND grant_token_digest > $1 \
             ORDER BY grant_token_digest LIMIT $2"
        );
        let rows = sql_query(query)
            .bind::<Text, _>(after_digest.unwrap_or(""))
            .bind::<BigInt, _>(limit)
            .load::<HardLogoutJournalRow>(&mut conn)
            .await
            .map_err(PersistenceError::database)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn mark_hard_logout_auth_confirmed(
        &self,
        grant_token_digest: &str,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let changed = sql_query(
            "UPDATE push_hard_logout_journal SET auth_side_confirmed = TRUE \
             WHERE grant_token_digest = $1",
        )
        .bind::<Text, _>(grant_token_digest)
        .execute(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        if changed != 1 {
            return Err(PersistenceError::NotFound("hard logout journal".to_owned()));
        }
        Ok(())
    }

    async fn mark_hard_logout_completed(
        &self,
        grant_token_digest: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<()> {
        let mut conn = pg_conn(&self.pool).await?;
        let changed = sql_query(
            "UPDATE push_hard_logout_journal SET completed_at = COALESCE(completed_at, $2) \
             WHERE grant_token_digest = $1 AND auth_side_confirmed = TRUE",
        )
        .bind::<Text, _>(grant_token_digest)
        .bind::<Timestamptz, _>(now)
        .execute(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        if changed != 1 {
            return Err(PersistenceError::Conflict(
                "cas_conflict: hard logout Auth-side completion is unconfirmed".to_owned(),
            ));
        }
        Ok(())
    }

    async fn ensure_desired_intent(
        &self,
        source_station_id: &DidCoreId,
        local_route: &PushRegistrationHandoffRouteLocator,
        device_authorization: &coland_storage::DeviceRevocationGateSelector,
        client_input_digest: &Hash,
        request: &PushRegistrationHandoffRequestBody,
        session_revocation_ref: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<PushRegistrationHandoffIntentWrite> {
        let candidate = PushRegistrationHandoffIntentRecord::prepare(
            source_station_id.clone(),
            local_route.clone(),
            device_authorization.clone(),
            client_input_digest.clone(),
            request,
            now,
        )?;
        let account_lock_key = push_device_lock_key(
            &candidate.local_route.account_id,
            candidate.local_route.device_id.as_str(),
        );
        let route_lock_key = local_route_lock_key(source_station_id, local_route)?;
        let session_revocation_ref = session_revocation_ref.map(str::to_owned);
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            crate::device_revocations::lock_artifact_devices_in_transaction(
                conn,
                &[&candidate.device_authorization],
            )
            .await?;
            crate::device_revocations::ensure_gate_not_revoked_in_transaction(
                conn,
                &candidate.device_authorization,
            )
            .await?;
            if let Some(revocation_ref) = &session_revocation_ref {
                ensure_logout_family_not_fenced(conn, revocation_ref).await?;
            }
            if candidate.desired_state
                == arkret_models_integration::PushRegistrationHandoffState::Active
            {
                ensure_active_account_in_transaction(conn, &candidate.local_route.account_id)
                    .await?;
            }
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&account_lock_key)
                .execute(conn)
                .await?;
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&route_lock_key)
                .execute(conn)
                .await?;

            if let Some(stored) = load_intent(
                conn,
                &candidate.source_station_id,
                &candidate.registration_id,
                true,
            )
            .await?
            {
                let outcome = apply_push_registration_desired_intent(&stored, &candidate)?;
                let PushRegistrationHandoffIntentWrite::AdvancedToRevoked(revoked) = &outcome
                else {
                    return Ok(outcome);
                };
                let updated = sql_query(
                    "UPDATE push_registration_handoff_intents \
                     SET desired_state = $5, request_digest = $6, client_input_digest = $7, \
                         canonical_request = $8, status = $9, receipt = NULL, updated_at = $10 \
                     WHERE source_station_id = $1 AND registration_id = $2 \
                       AND destination_gateway_id = $3 AND request_digest = $4 \
                       AND desired_state = 'active'",
                )
                .bind::<Text, _>(&stored.source_station_id)
                .bind::<Text, _>(stored.registration_id.as_str())
                .bind::<Text, _>(&stored.destination_gateway_id)
                .bind::<Text, _>(stored.request_digest.as_str())
                .bind::<Text, _>(revoked.desired_state.as_str())
                .bind::<Text, _>(revoked.request_digest.as_str())
                .bind::<Text, _>(revoked.client_input_digest.as_str())
                .bind::<Binary, _>(&revoked.canonical_request)
                .bind::<Text, _>(revoked.status.as_str())
                .bind::<Timestamptz, _>(revoked.updated_at)
                .execute(conn)
                .await?;
                if updated != 1 {
                    return Err(PersistenceError::Conflict(
                        "cas_conflict: push registration handoff desired state changed".to_owned(),
                    )
                    .into());
                }
                return Ok(outcome);
            }

            if let Some(stored) = load_local_route_intent(
                conn,
                &candidate.source_station_id,
                &candidate.local_route,
                true,
            )
            .await?
                && stored.status == PushRegistrationHandoffIntentStatus::AwaitingReceipt
            {
                if stored.client_input_digest == candidate.client_input_digest
                    && stored.desired_state == candidate.desired_state
                {
                    return Ok(PushRegistrationHandoffIntentWrite::ExactReplay(stored));
                }
                return Err(PersistenceError::Conflict(
                    "cas_conflict: push handoff local route already has another awaiting client intent"
                        .to_owned(),
                )
                .into());
            }

            let inserted = sql_query(
                "INSERT INTO push_registration_handoff_intents \
                 (source_station_id, local_account_id, local_device_id, local_push_route_id, \
                  device_authorization, registration_id, destination_gateway_id, desired_state, \
                  request_digest, client_input_digest, canonical_request, status, receipt, \
                  created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NULL, $13, $13) \
                 ON CONFLICT (source_station_id, registration_id) DO NOTHING",
            )
            .bind::<Text, _>(&candidate.source_station_id)
            .bind::<Jsonb, _>(
                serde_json::to_value(&candidate.local_route.account_id)
                    .map_err(PersistenceError::database)?,
            )
            .bind::<Text, _>(candidate.local_route.device_id.as_str())
            .bind::<Text, _>(&candidate.local_route.push_route_id)
            .bind::<Jsonb, _>(
                serde_json::to_value(&candidate.device_authorization)
                    .map_err(PersistenceError::database)?,
            )
            .bind::<Text, _>(candidate.registration_id.as_str())
            .bind::<Text, _>(&candidate.destination_gateway_id)
            .bind::<Text, _>(candidate.desired_state.as_str())
            .bind::<Text, _>(candidate.request_digest.as_str())
            .bind::<Text, _>(candidate.client_input_digest.as_str())
            .bind::<Binary, _>(&candidate.canonical_request)
            .bind::<Text, _>(candidate.status.as_str())
            .bind::<Timestamptz, _>(candidate.created_at)
            .execute(conn)
            .await?;
            if inserted == 1 {
                return Ok(PushRegistrationHandoffIntentWrite::Created(candidate));
            }
            let stored = load_intent(
                conn,
                &candidate.source_station_id,
                &candidate.registration_id,
                true,
            )
            .await?
            .ok_or_else(|| {
                PersistenceError::Internal(
                    "push registration handoff conflict row disappeared".to_owned(),
                )
            })?;
            apply_push_registration_desired_intent(&stored, &candidate).map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn get_intent(
        &self,
        source_station_id: &DidCoreId,
        registration_id: &PushRegistrationId,
    ) -> PersistenceResult<Option<PushRegistrationHandoffIntentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_intent(&mut conn, source_station_id, registration_id, false).await
    }

    async fn lookup_local_route_intent(
        &self,
        source_station_id: &DidCoreId,
        local_route: &PushRegistrationHandoffRouteLocator,
    ) -> PersistenceResult<Option<PushRegistrationHandoffIntentRecord>> {
        let mut conn = pg_conn(&self.pool).await?;
        load_local_route_intent(&mut conn, source_station_id, local_route, false).await
    }

    async fn commit_verified_receipt(
        &self,
        source_station_id: &DidCoreId,
        registration_id: &PushRegistrationId,
        expected_request_digest: &Hash,
        receipt: &PushRegistrationInstallationReceipt,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<PushRegistrationHandoffReceiptWrite> {
        let source_station_id = source_station_id.clone();
        let registration_id = registration_id.clone();
        let expected_request_digest = expected_request_digest.clone();
        let receipt = receipt.clone();
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            let record = load_intent(conn, &source_station_id, &registration_id, true)
                .await?
                .ok_or_else(|| {
                    PersistenceError::NotFound(
                        "push registration handoff desired intent".to_owned(),
                    )
                })?;
            let outcome = apply_verified_push_registration_receipt(
                &record,
                &expected_request_digest,
                &receipt,
                now,
            )?;
            store_receipt_transition(
                conn,
                &source_station_id,
                &registration_id,
                &expected_request_digest,
                &outcome,
            )
            .await?;
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn begin_public_push_unregistration(
        &self,
        account_id: &AccountId,
        device_id: &DeviceId,
        push_key: Option<&str>,
        app_id: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<Vec<PushRegistrationHandoffIntentRecord>> {
        account_id
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let revoke_input_digest =
            public_unregistration_input_digest(account_id, device_id, push_key, app_id)?;
        let account_id = account_id.clone();
        let device_id = device_id.clone();
        let push_key = push_key.map(str::to_owned);
        let app_id = app_id.map(str::to_owned);
        let account_json = serde_json::to_value(&account_id).map_err(PersistenceError::database)?;
        let account_lock_key = push_device_lock_key(&account_id, device_id.as_str());
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // The active-receipt UOW takes the same account/device lock before
            // handoff route and intent locks, so replacement and revoke cannot
            // deadlock or make a deleted route deliverable again.
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&account_lock_key)
                .execute(&mut *conn)
                .await?;
            let routes = sql_query(
                "SELECT payload, device_authorization, public_handoff FROM push_devices \
                 WHERE payload->'account_id' = $1 AND device_id = $2 \
                   AND ($3 IS NULL OR push_key = $3) \
                   AND ($4 IS NULL OR app_id = $4) \
                 ORDER BY payload->>'push_route_id', id",
            )
            .bind::<Jsonb, _>(&account_json)
            .bind::<Text, _>(device_id.as_str())
            .bind::<Nullable<Text>, _>(push_key.as_deref())
            .bind::<Nullable<Text>, _>(app_id.as_deref())
            .load::<CurrentPushRouteRow>(&mut *conn)
            .await?;
            let awaiting_query = format!(
                "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
                 WHERE source_station_id = $1 AND local_account_id = $2 \
                   AND local_device_id = $3 AND desired_state = 'active' \
                   AND status = 'awaiting_receipt' \
                 ORDER BY local_push_route_id, destination_gateway_id, registration_id"
            );
            let awaiting = sql_query(awaiting_query)
                .bind::<Text, _>(&account_id.station_id)
                .bind::<Jsonb, _>(&account_json)
                .bind::<Text, _>(device_id.as_str())
                .load::<HandoffIntentRow>(&mut *conn)
                .await?;
            let replay_query = format!(
                "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
                 WHERE source_station_id = $1 AND local_account_id = $2 \
                   AND local_device_id = $3 AND desired_state = 'revoked' \
                   AND status = 'awaiting_receipt' AND client_input_digest = $4 \
                 ORDER BY local_push_route_id, destination_gateway_id, registration_id"
            );
            let mut revoked = sql_query(replay_query)
                .bind::<Text, _>(&account_id.station_id)
                .bind::<Jsonb, _>(&account_json)
                .bind::<Text, _>(device_id.as_str())
                .bind::<Text, _>(revoke_input_digest.as_str())
                .load::<HandoffIntentRow>(&mut *conn)
                .await?
                .into_iter()
                .map(TryInto::try_into)
                .collect::<PersistenceResult<Vec<_>>>()?;
            for snapshot in awaiting {
                let snapshot: PushRegistrationHandoffIntentRecord = snapshot.try_into()?;
                let request = snapshot.request()?;
                if !active_request_matches_filters(
                    &request,
                    push_key.as_deref(),
                    app_id.as_deref(),
                ) {
                    continue;
                }
                let route_lock_key =
                    local_route_lock_key(&account_id.station_id, &snapshot.local_route)?;
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                    .bind::<Text, _>(&route_lock_key)
                    .execute(&mut *conn)
                    .await?;
                let stored = load_intent(
                    conn,
                    &account_id.station_id,
                    &snapshot.registration_id,
                    true,
                )
                .await?
                .ok_or_else(|| {
                    PersistenceError::Conflict(
                        "cas_conflict: pending public push handoff disappeared during unregistration"
                            .to_owned(),
                    )
                })?;
                if stored.local_route != snapshot.local_route
                    || stored.local_route.account_id != account_id
                    || stored.local_route.device_id != device_id
                    || stored.desired_state
                        != arkret_models_integration::PushRegistrationHandoffState::Active
                {
                    return Err(PersistenceError::Conflict(
                        "cas_conflict: pending public push handoff changed during unregistration"
                            .to_owned(),
                    )
                    .into());
                }
                revoked.push(
                    advance_active_intent_to_revoked(
                        conn,
                        &stored,
                        &revoke_input_digest,
                        now,
                    )
                    .await?,
                );
            }
            for route_row in routes {
                if !route_row.public_handoff {
                    continue;
                }
                let registration: PushRegistrationRecord =
                    serde_json::from_value(route_row.payload.clone()).map_err(|error| {
                        PersistenceError::Internal(format!(
                            "stored push route is invalid during public unregistration: {error}"
                        ))
                    })?;
                let registration_id =
                    PushRegistrationId::new(registration.registration_id.as_str().to_owned())
                        .map_err(|error| {
                            PersistenceError::Internal(format!(
                                "stored public push route has invalid registration identity: {error}"
                            ))
                        })?;
                let snapshot = load_intent(
                    conn,
                    &account_id.station_id,
                    &registration_id,
                    false,
                )
                .await?
                .ok_or_else(|| {
                    PersistenceError::Conflict(
                        "cas_conflict: public push route has no durable handoff".to_owned(),
                    )
                })?;
                let route_lock_key =
                    local_route_lock_key(&account_id.station_id, &snapshot.local_route)?;
                sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                    .bind::<Text, _>(&route_lock_key)
                    .execute(&mut *conn)
                    .await?;
                let stored = load_intent(conn, &account_id.station_id, &registration_id, true)
                    .await?
                    .ok_or_else(|| {
                        PersistenceError::Conflict(
                            "cas_conflict: public push handoff disappeared during unregistration"
                                .to_owned(),
                        )
                    })?;
                let route_authorization: coland_storage::DeviceRevocationGateSelector =
                    serde_json::from_value(route_row.device_authorization.clone()).map_err(
                        |error| {
                            PersistenceError::Internal(format!(
                                "stored push route authorization is invalid: {error}"
                            ))
                        },
                    )?;
                if stored.status != PushRegistrationHandoffIntentStatus::ReceiptVerified
                    || stored.desired_state
                        != arkret_models_integration::PushRegistrationHandoffState::Active
                    || stored.device_authorization != route_authorization
                    || stored.local_route.account_id != account_id
                    || stored.local_route.device_id != device_id
                    || stored.local_route.push_route_id != registration.push_route_id
                    || stored.registration_id != registration_id
                {
                    return Err(PersistenceError::Conflict(
                        "cas_conflict: current public push route differs from its handoff intent"
                            .to_owned(),
                    )
                    .into());
                }
                let active = stored.request()?;
                let PushRegistrationHandoffRequestBody::Active {
                    push_target_id,
                    device_id: request_device_id,
                    push_key: request_push_key,
                    platform,
                    app_id: request_app_id,
                    visible_notification_opt_in,
                    expires_at,
                    ..
                } = active
                else {
                    return Err(PersistenceError::Conflict(
                        "cas_conflict: current public push route has no active handoff".to_owned(),
                    )
                    .into());
                };
                if registration.push_target_id != push_target_id
                    || registration.device_id != request_device_id
                    || registration.push_key != request_push_key
                    || registration.platform != platform
                    || registration.app_id != request_app_id
                    || registration.visible_notification_opt_in != visible_notification_opt_in
                    || registration.expires_at != expires_at
                {
                    return Err(PersistenceError::Conflict(
                        "cas_conflict: current public push route payload differs from its handoff"
                            .to_owned(),
                    )
                    .into());
                }
                let revoked_record = advance_active_intent_to_revoked(
                    conn,
                    &stored,
                    &revoke_input_digest,
                    now,
                )
                .await?;
                let removed = sql_query(
                    "DELETE FROM push_devices WHERE payload->'account_id' = $1 \
                       AND device_id = $2 AND payload->>'push_route_id' = $3 \
                       AND id = $4 AND device_authorization = $5",
                )
                .bind::<Jsonb, _>(&account_json)
                .bind::<Text, _>(device_id.as_str())
                .bind::<Text, _>(&registration.push_route_id)
                .bind::<Text, _>(registration.registration_id.as_str())
                .bind::<Jsonb, _>(&route_row.device_authorization)
                .execute(&mut *conn)
                .await?;
                if removed != 1 {
                    return Err(PersistenceError::Conflict(
                        "cas_conflict: public push route changed during unregistration".to_owned(),
                    )
                    .into());
                }
                revoked.push(revoked_record);
            }
            Ok(revoked)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }

    async fn begin_public_push_account_deactivation(
        &self,
        account_id: &AccountId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<usize> {
        account_id
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let account_json = serde_json::to_value(account_id).map_err(PersistenceError::database)?;
        let mut conn = pg_conn(&self.pool).await?;
        let lifecycle = sql_query(
            "SELECT l.state FROM account_lifecycle l JOIN accounts a ON a.pk = l.account_pk \
             WHERE a.principal_id = $1 AND a.station_id = $2",
        )
        .bind::<Text, _>(&account_id.principal_id)
        .bind::<Text, _>(&account_id.station_id)
        .get_result::<AccountLifecycleStateRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if !lifecycle.is_some_and(|lifecycle| {
            matches!(lifecycle.state.as_str(), "deactivated" | "erasure_pending")
        }) {
            return Err(PersistenceError::Conflict(
                "cas_conflict: public push account deactivation requires a terminal account"
                    .to_owned(),
            ));
        }
        // Include pending intents even when a device inventory row is gone,
        // and include public routes with missing intents so the normal UOW
        // detects the inconsistency instead of silently leaving them live.
        let devices = sql_query(
            "SELECT DISTINCT local_device_id AS device_id \
             FROM push_registration_handoff_intents \
             WHERE source_station_id = $1 AND local_account_id = $2 \
               AND desired_state = 'active' \
             UNION \
             SELECT DISTINCT device_id FROM push_devices \
             WHERE payload->'account_id' = $2 AND public_handoff = TRUE \
             ORDER BY device_id",
        )
        .bind::<Text, _>(&account_id.station_id)
        .bind::<Jsonb, _>(&account_json)
        .load::<PublicHandoffDeviceRow>(&mut conn)
        .await
        .map_err(PersistenceError::database)?;
        drop(conn);
        let mut revoked = 0usize;
        let mut first_error = None;
        for device in devices {
            let result = match DeviceId::new(device.device_id) {
                Ok(device_id) => {
                    self.begin_public_push_unregistration(account_id, &device_id, None, None, now)
                        .await
                }
                Err(error) => Err(PersistenceError::Internal(error.to_string())),
            };
            match result {
                Ok(intents) => revoked = revoked.saturating_add(intents.len()),
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(revoked)
    }

    async fn expire_public_push_registrations(
        &self,
        source_station_id: &DidCoreId,
        now: chrono::DateTime<chrono::Utc>,
        after: Option<&PushRegistrationHandoffExpiryCursor>,
        limit: usize,
    ) -> PersistenceResult<PushRegistrationHandoffExpiryPage> {
        if limit == 0 {
            return Ok(PushRegistrationHandoffExpiryPage::default());
        }
        let page_limit = limit.min(1_000);
        let limit = i64::try_from(page_limit).map_err(PersistenceError::database)?;
        let mut conn = pg_conn(&self.pool).await?;
        let query = if after.is_some() {
            format!(
                "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
                 WHERE source_station_id=$1 AND desired_state='active' \
                   AND (created_at > $2 OR (created_at = $2 AND registration_id > $3)) \
                 ORDER BY created_at, registration_id LIMIT $4"
            )
        } else {
            format!(
                "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
                 WHERE source_station_id=$1 AND desired_state='active' \
                 ORDER BY created_at, registration_id LIMIT $2"
            )
        };
        let rows = if let Some(after) = after {
            sql_query(query)
                .bind::<Text, _>(source_station_id)
                .bind::<Timestamptz, _>(after.created_at)
                .bind::<Text, _>(&after.registration_id)
                .bind::<BigInt, _>(limit)
                .load::<HandoffIntentRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?
        } else {
            sql_query(query)
                .bind::<Text, _>(source_station_id)
                .bind::<BigInt, _>(limit)
                .load::<HandoffIntentRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?
        };
        drop(conn);

        let next_cursor = if rows.len() == page_limit {
            rows.last().map(|row| PushRegistrationHandoffExpiryCursor {
                created_at: row.created_at,
                registration_id: row.registration_id.clone(),
            })
        } else {
            None
        };
        let mut page = PushRegistrationHandoffExpiryPage {
            scanned: rows.len(),
            next_cursor,
            ..PushRegistrationHandoffExpiryPage::default()
        };
        for row in rows {
            let snapshot: PushRegistrationHandoffIntentRecord = match row.try_into() {
                Ok(snapshot) => snapshot,
                Err(_) => {
                    page.failed += 1;
                    continue;
                }
            };
            let request = match snapshot.request() {
                Ok(request) => request,
                Err(_) => {
                    page.failed += 1;
                    continue;
                }
            };
            let PushRegistrationHandoffRequestBody::Active {
                expires_at: Some(expires_at),
                ..
            } = request
            else {
                continue;
            };
            if expires_at > now {
                continue;
            }
            match expire_public_push_registration(&self.pool, source_station_id, &snapshot, now)
                .await
            {
                Ok(Some(expired)) => page.expired.push(expired),
                Ok(None) => {}
                Err(_) => page.failed += 1,
            }
        }
        Ok(page)
    }

    async fn list_awaiting_revoked_intents(
        &self,
        source_station_id: &DidCoreId,
        after: Option<&PushRegistrationHandoffRetryCursor>,
        limit: usize,
    ) -> PersistenceResult<Vec<PushRegistrationHandoffIntentRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit.min(1_000)).map_err(PersistenceError::database)?;
        let mut conn = pg_conn(&self.pool).await?;
        let rows = if let Some(after) = after {
            let query = format!(
                "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
                 WHERE source_station_id = $1 AND desired_state = 'revoked' \
                   AND status = 'awaiting_receipt' \
                   AND (updated_at > $2 OR (updated_at = $2 AND registration_id > $3)) \
                 ORDER BY updated_at, registration_id LIMIT $4"
            );
            sql_query(query)
                .bind::<Text, _>(source_station_id)
                .bind::<Timestamptz, _>(after.updated_at)
                .bind::<Text, _>(after.registration_id.as_str())
                .bind::<BigInt, _>(limit)
                .load::<HandoffIntentRow>(&mut conn)
                .await
                .map_err(PersistenceError::database)?
        } else {
            let query = format!(
                "SELECT {HANDOFF_COLUMNS} FROM push_registration_handoff_intents \
                 WHERE source_station_id = $1 AND desired_state = 'revoked' \
                   AND status = 'awaiting_receipt' \
                 ORDER BY updated_at, registration_id LIMIT $2"
            );
            sql_query(query)
                .bind::<Text, _>(source_station_id)
                .bind::<BigInt, _>(limit)
                .load::<HandoffIntentRow>(&mut conn)
                .await
                .map_err(PersistenceError::database)?
        };
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn commit_verified_active_receipt_and_push_route(
        &self,
        source_station_id: &DidCoreId,
        local_route: &PushRegistrationHandoffRouteLocator,
        registration_id: &PushRegistrationId,
        expected_request_digest: &Hash,
        receipt: &PushRegistrationInstallationReceipt,
        authorization: &coland_storage::DeviceRevocationGateSelector,
        registration: &PushRegistrationRecord,
        session_revocation_ref: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> PersistenceResult<PushRegistrationHandoffReceiptWrite> {
        let source_station_id = source_station_id.clone();
        let local_route = local_route.clone();
        let registration_id = registration_id.clone();
        let expected_request_digest = expected_request_digest.clone();
        let receipt = receipt.clone();
        let authorization = authorization.clone();
        let registration = registration.clone();
        let session_revocation_ref = session_revocation_ref.map(str::to_owned);
        let account_lock_key =
            push_device_lock_key(&registration.account_id, registration.device_id.as_str());
        let route_lock_key = local_route_lock_key(&source_station_id, &local_route)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            // Lock order: live device gate, account/device, handoff route,
            // handoff intent, then the local push-device route.
            crate::device_revocations::lock_artifact_devices_in_transaction(
                conn,
                &[&authorization],
            )
            .await?;
            crate::ensure_gate_allowed_in_transaction(conn, &authorization).await?;
            if let Some(revocation_ref) = &session_revocation_ref {
                ensure_logout_family_not_fenced(conn, revocation_ref).await?;
            }
            ensure_active_account_in_transaction(conn, &registration.account_id).await?;
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&account_lock_key)
                .execute(conn)
                .await?;
            sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind::<Text, _>(&route_lock_key)
                .execute(conn)
                .await?;
            let record = load_intent(conn, &source_station_id, &registration_id, true)
                .await?
                .ok_or_else(|| {
                    PersistenceError::NotFound(
                        "push registration handoff desired intent".to_owned(),
                    )
                })?;
            if record.local_route != local_route {
                return Err(PersistenceError::Conflict(
                    "cas_conflict: push handoff intent belongs to another local route".to_owned(),
                )
                .into());
            }
            record.validate_active_local_registration(&authorization, &registration)?;
            let outcome = apply_verified_push_registration_receipt(
                &record,
                &expected_request_digest,
                &receipt,
                now,
            )?;
            let mode = match &outcome {
                PushRegistrationHandoffReceiptWrite::Stored(_) => {
                    PushDeviceRouteWriteMode::AllowReplace
                }
                PushRegistrationHandoffReceiptWrite::ExactReplay(_) => {
                    PushDeviceRouteWriteMode::RequireExact
                }
            };
            write_push_device_route_in_transaction(
                conn,
                &authorization,
                registration,
                now,
                mode,
                true,
            )
            .await?;
            store_receipt_transition(
                conn,
                &source_station_id,
                &registration_id,
                &expected_request_digest,
                &outcome,
            )
            .await?;
            Ok(outcome)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arkret_models_integration::PushRegistrationHandoffState;
    use arkret_wire::{AccountId, Audience, DeviceId, DidUrl, PayloadProof};
    use coland_storage::{DeviceRevocationStore, PushDeviceStore};
    use serde_json::json;
    use tokio::sync::Barrier;

    use super::*;
    use crate::device_authorization_history::did_web_station;
    use crate::pcr_genesis::PcrGenesisFixture;
    use crate::{PgDeviceRevocationStore, PgPersistenceStore, PgPushDeviceStore};

    fn active_request() -> PushRegistrationHandoffRequestBody {
        active_request_with_id("registration_0123456789abcdef", None)
    }

    fn active_request_with_id(
        registration_id: &str,
        supersedes_registration_id: Option<&PushRegistrationId>,
    ) -> PushRegistrationHandoffRequestBody {
        serde_json::from_value(json!({
            "registration_id": registration_id,
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": "provider-secret",
            "platform": "apns",
            "app_id": "com.example.app",
            "visible_notification_opt_in": false,
            "supersedes_registration_id": supersedes_registration_id
        }))
        .unwrap()
    }

    fn local_route_for_account(
        account_id: AccountId,
        device_id: DeviceId,
        destination: &DidCoreId,
    ) -> PushRegistrationHandoffRouteLocator {
        PushRegistrationHandoffRouteLocator {
            account_id,
            device_id,
            push_route_id: "com.example.app".to_owned(),
            destination_gateway_id: destination.clone(),
        }
    }

    async fn seed_account(pool: &PgPool, account: &AccountId) {
        let mut conn = pg_conn(pool).await.unwrap();
        sql_query(
            "INSERT INTO accounts (principal_id, station_id) VALUES ($1, $2) \
             ON CONFLICT (station_id, principal_id) DO NOTHING",
        )
        .bind::<Text, _>(&account.principal_id)
        .bind::<Text, _>(&account.station_id)
        .execute(&mut conn)
        .await
        .unwrap();
    }

    /// Admit a genuinely signed PCR genesis at `source` and return the local
    /// route of its founding device with the selector the Station accepted.
    async fn accepted_local_route(
        pool: &PgPool,
        source: &DidCoreId,
        destination: &DidCoreId,
    ) -> (
        PushRegistrationHandoffRouteLocator,
        coland_storage::DeviceRevocationGateSelector,
    ) {
        {
            let mut conn = pool.get().await.unwrap();
            sql_query(
                "INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1) \
                 ON CONFLICT(singleton) DO NOTHING",
            )
            .bind::<Text, _>(source.as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        }
        let fixture = PcrGenesisFixture::new(did_web_station(source));
        let authorization = fixture
            .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
            .await
            .expect("accepted PCR genesis");
        let route = local_route_for_account(
            fixture.history.account.clone(),
            fixture.history.founding_device_id.clone(),
            destination,
        );
        seed_account(pool, &route.account_id).await;
        (route, authorization)
    }

    fn client_input_digest(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn active_request_for_device(
        registration_id: &str,
        device_id: &DeviceId,
        push_target_id: &str,
        push_key: &str,
    ) -> PushRegistrationHandoffRequestBody {
        active_request_for_route(
            registration_id,
            device_id,
            push_target_id,
            push_key,
            "com.example.app",
        )
    }

    fn active_request_for_route(
        registration_id: &str,
        device_id: &DeviceId,
        push_target_id: &str,
        push_key: &str,
        app_id: &str,
    ) -> PushRegistrationHandoffRequestBody {
        active_request_for_route_superseding(
            registration_id,
            device_id,
            push_target_id,
            push_key,
            app_id,
            None,
        )
    }

    fn active_request_expiring_at(
        registration_id: &str,
        device_id: &DeviceId,
        push_target_id: &str,
        push_key: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> PushRegistrationHandoffRequestBody {
        let mut value = serde_json::to_value(active_request_for_device(
            registration_id,
            device_id,
            push_target_id,
            push_key,
        ))
        .unwrap();
        value["expires_at"] =
            Value::String(arkret_canonical::format_timestamp_canonical(expires_at));
        serde_json::from_value(value).unwrap()
    }

    fn active_request_for_route_superseding(
        registration_id: &str,
        device_id: &DeviceId,
        push_target_id: &str,
        push_key: &str,
        app_id: &str,
        supersedes_registration_id: Option<&PushRegistrationId>,
    ) -> PushRegistrationHandoffRequestBody {
        serde_json::from_value(json!({
            "registration_id": registration_id,
            "push_target_id": push_target_id,
            "device_id": device_id,
            "state": "active",
            "push_key": push_key,
            "platform": "apns",
            "app_id": app_id,
            "visible_notification_opt_in": false,
            "supersedes_registration_id": supersedes_registration_id
        }))
        .unwrap()
    }

    fn local_registration(
        account_id: &AccountId,
        request: &PushRegistrationHandoffRequestBody,
    ) -> PushRegistrationRecord {
        let PushRegistrationHandoffRequestBody::Active {
            registration_id,
            push_target_id,
            device_id,
            push_key,
            platform,
            app_id,
            visible_notification_opt_in,
            expires_at,
            ..
        } = request
        else {
            panic!("test registration request must be active")
        };
        PushRegistrationRecord {
            registration_id: arkret_wire::OpaqueLocalId::new(registration_id.as_str()).unwrap(),
            account_id: account_id.clone(),
            device_id: device_id.clone(),
            push_gateway: "https://push.example/".to_owned(),
            push_key: push_key.clone(),
            platform: platform.clone(),
            app_id: app_id.clone(),
            visible_notification_opt_in: *visible_notification_opt_in,
            push_route_id: "com.example.app".to_owned(),
            push_target_id: push_target_id.clone(),
            salt_epoch_id: "ak.push.salt_epoch.42".to_owned(),
            expires_at: *expires_at,
            retained_push_targets: Vec::new(),
        }
    }

    #[derive(QueryableByName)]
    struct StoredPushRoute {
        #[diesel(sql_type = Jsonb)]
        payload: Value,
        #[diesel(sql_type = Timestamptz)]
        updated_at: chrono::DateTime<chrono::Utc>,
    }

    async fn stored_push_route(
        pool: &PgPool,
        route: &PushRegistrationHandoffRouteLocator,
    ) -> Option<StoredPushRoute> {
        let account = serde_json::to_value(&route.account_id).unwrap();
        let mut conn = pool.get().await.unwrap();
        sql_query(
            "SELECT payload, updated_at FROM push_devices \
             WHERE payload->'account_id'=$1 AND device_id=$2 \
               AND payload->>'push_route_id'=$3",
        )
        .bind::<Jsonb, _>(&account)
        .bind::<Text, _>(route.device_id.as_str())
        .bind::<Text, _>(&route.push_route_id)
        .get_result::<StoredPushRoute>(&mut *conn)
        .await
        .optional()
        .unwrap()
    }

    async fn install_public_route(
        store: &PgPushRegistrationHandoffStore,
        station_id: &DidCoreId,
        route: &PushRegistrationHandoffRouteLocator,
        authorization: &coland_storage::DeviceRevocationGateSelector,
        request: &PushRegistrationHandoffRequestBody,
        client_digest: &Hash,
        at: chrono::DateTime<chrono::Utc>,
    ) {
        store
            .ensure_desired_intent(
                station_id,
                route,
                authorization,
                client_digest,
                request,
                None,
                at,
            )
            .await
            .unwrap();
        let receipt = receipt_for(
            request,
            station_id,
            &route.destination_gateway_id,
            at + chrono::Duration::milliseconds(1),
        );
        let mut registration = local_registration(&route.account_id, request);
        registration.push_route_id = route.push_route_id.clone();
        store
            .commit_verified_active_receipt_and_push_route(
                station_id,
                route,
                request.registration_id(),
                &request.request_digest().unwrap(),
                &receipt,
                authorization,
                &registration,
                None,
                at + chrono::Duration::milliseconds(2),
            )
            .await
            .unwrap();
    }

    fn receipt_for(
        request: &PushRegistrationHandoffRequestBody,
        source: &DidCoreId,
        destination: &DidCoreId,
        stored_at: chrono::DateTime<chrono::Utc>,
    ) -> PushRegistrationInstallationReceipt {
        let mut receipt = PushRegistrationInstallationReceipt {
            registration_id: request.registration_id().clone(),
            push_target_id: request.push_target_id().clone(),
            device_id: request.device_id().clone(),
            state: request.state(),
            request_digest: request.request_digest().unwrap(),
            source_station_id: source.clone(),
            destination_gateway_id: destination.clone(),
            stored_at,
            proof: PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(format!(
                    "did:{}#push-receipt-key",
                    destination
                        .as_str()
                        .strip_prefix("ak:did_core:")
                        .expect("test destination is a projected DID")
                ))
                .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: stored_at,
                domain: None,
                audience: Some(Audience::Single(source.as_str().to_owned())),
                proof_purpose: None,
                jws: "fixture..signature".to_owned(),
            },
        };
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        receipt
    }

    #[tokio::test]
    async fn hard_logout_family_fence_survives_retry_and_restart_scan() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let source = DidCoreId::new("ak:did_core:web:source.example").unwrap();
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let (route, authorization) = accepted_local_route(&pool, &source, &destination).await;
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        let active = active_request();
        let at = chrono::Utc::now();
        store
            .ensure_desired_intent(
                &source,
                &route,
                &authorization,
                &client_input_digest('1'),
                &active,
                Some("org.arkret.coauth.browser_session:fixture"),
                at,
            )
            .await
            .unwrap();
        let record = PushHardLogoutJournalRecord {
            grant_token_digest: "grant-digest-one".to_owned(),
            revocation_ref: "org.arkret.coauth.browser_session:fixture".to_owned(),
            account_id: route.account_id.clone(),
            device_id: route.device_id.clone(),
            cnf_jkt: "fixture-jkt".to_owned(),
            auth_side_confirmed: false,
            completed_at: None,
            created_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        };
        assert_eq!(
            store.reserve_hard_logout_journal(&record).await.unwrap(),
            record
        );
        assert_eq!(
            store.reserve_hard_logout_journal(&record).await.unwrap(),
            record
        );
        let mut changed = record.clone();
        changed.grant_token_digest = "grant-digest-two".to_owned();
        changed.device_id =
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap();
        assert!(matches!(
            store.reserve_hard_logout_journal(&changed).await,
            Err(PersistenceError::Conflict(_))
        ));
        changed.device_id = record.device_id.clone();
        changed.account_id.principal_id = DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(matches!(
            store.reserve_hard_logout_journal(&changed).await,
            Err(PersistenceError::Conflict(_))
        ));
        assert!(matches!(
            store
                .ensure_desired_intent(
                    &source,
                    &route,
                    &authorization,
                    &client_input_digest('1'),
                    &active_request(),
                    Some(&record.revocation_ref),
                    chrono::Utc::now(),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        let receipt = receipt_for(&active, &source, &destination, at);
        let registration = local_registration(&route.account_id, &active);
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &source,
                    &route,
                    active.registration_id(),
                    &active.request_digest().unwrap(),
                    &receipt,
                    &authorization,
                    &registration,
                    Some(&record.revocation_ref),
                    at,
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        store
            .mark_hard_logout_auth_confirmed(&record.grant_token_digest)
            .await
            .unwrap();
        let restarted_store = PgPushRegistrationHandoffStore { pool };
        let pending = restarted_store
            .pending_confirmed_hard_logouts(None, 64)
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].grant_token_digest, record.grant_token_digest);
        restarted_store
            .mark_hard_logout_completed(&record.grant_token_digest, chrono::Utc::now())
            .await
            .unwrap();
        assert!(
            restarted_store
                .pending_confirmed_hard_logouts(None, 64)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn inactive_account_cannot_create_or_install_a_public_handoff() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let source = DidCoreId::new("ak:did_core:web:source.example").unwrap();
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let (route, authorization) = accepted_local_route(&pool, &source, &destination).await;
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        let active = active_request();
        let at = chrono::Utc::now();
        store
            .ensure_desired_intent(
                &source,
                &route,
                &authorization,
                &client_input_digest('1'),
                &active,
                None,
                at,
            )
            .await
            .unwrap();
        let mut conn = pg_conn(&pool).await.unwrap();
        sql_query(
            "INSERT INTO account_lifecycle (account_pk, state, changed_at) \
             SELECT pk, 'deactivated', $3 FROM accounts \
             WHERE principal_id = $1 AND station_id = $2",
        )
        .bind::<Text, _>(&route.account_id.principal_id)
        .bind::<Text, _>(&route.account_id.station_id)
        .bind::<Timestamptz, _>(at)
        .execute(&mut conn)
        .await
        .unwrap();
        let new_active = active_request_with_id(
            "registration_bbbbbbbbbbbbbbbb",
            Some(active.registration_id()),
        );
        assert!(matches!(
            store
                .ensure_desired_intent(
                    &source,
                    &route,
                    &authorization,
                    &client_input_digest('2'),
                    &new_active,
                    None,
                    at,
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        let receipt = receipt_for(&active, &source, &destination, at);
        let registration = local_registration(&route.account_id, &active);
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &source,
                    &route,
                    active.registration_id(),
                    &active.request_digest().unwrap(),
                    &receipt,
                    &authorization,
                    &registration,
                    None,
                    at,
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        assert_eq!(
            store
                .begin_public_push_account_deactivation(&route.account_id, at)
                .await
                .unwrap(),
            1
        );
        let tombstone = store
            .get_intent(&source, active.registration_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            tombstone.desired_state,
            PushRegistrationHandoffState::Revoked
        );
        assert_eq!(
            tombstone.status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );
    }

    #[tokio::test]
    async fn deactivated_account_stops_public_delivery_before_revoke_fanout() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let fixture = PcrGenesisFixture::new(did_web_station(&station_id));
        let source = &fixture.history;
        seed_account(&pool, &source.account).await;
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
                .bind::<Text, _>(station_id.as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let authorization = fixture
            .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
            .await
            .expect("accepted PCR genesis");
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route = local_route_for_account(
            source.account.clone(),
            source.founding_device_id.clone(),
            &destination,
        );
        let request = active_request_for_device(
            "registration_9999999999999999",
            &source.founding_device_id,
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "provider-token",
        );
        let at = chrono::Utc::now();
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        install_public_route(
            &store,
            &station_id,
            &route,
            &authorization,
            &request,
            &client_input_digest('e'),
            at,
        )
        .await;
        let push = PgPushDeviceStore { pool: pool.clone() };
        assert_eq!(push.snapshot_all().await.unwrap().len(), 1);
        let mut conn = pg_conn(&pool).await.unwrap();
        sql_query(
            "INSERT INTO account_lifecycle (account_pk, state, changed_at) \
             SELECT pk, 'deactivated', $3 FROM accounts \
             WHERE principal_id = $1 AND station_id = $2",
        )
        .bind::<Text, _>(&source.account.principal_id)
        .bind::<Text, _>(&source.account.station_id)
        .bind::<Timestamptz, _>(at)
        .execute(&mut conn)
        .await
        .unwrap();
        drop(conn);
        assert!(stored_push_route(&pool, &route).await.is_some());
        assert!(
            push.snapshot_all().await.unwrap().is_empty(),
            "the durable account lifecycle gate must stop delivery before fanout"
        );
        assert_eq!(
            store
                .begin_public_push_account_deactivation(&source.account, at)
                .await
                .unwrap(),
            1
        );
        assert!(stored_push_route(&pool, &route).await.is_none());
        let tombstone = store
            .get_intent(&station_id, request.registration_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            tombstone.desired_state,
            PushRegistrationHandoffState::Revoked
        );
        assert_eq!(
            tombstone.status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );
    }

    #[tokio::test]
    async fn concurrent_revoke_wins_over_active_receipt_and_late_receipt_fails_cas() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        let source = DidCoreId::new("ak:did_core:web:source.example").unwrap();
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let (route, authorization) = accepted_local_route(&pool, &source, &destination).await;
        let active_client_digest = client_input_digest('1');
        let active = active_request();
        let active_digest = active.request_digest().unwrap();
        let started_at = chrono::Utc::now();
        assert!(matches!(
            store
                .ensure_desired_intent(
                    &source,
                    &route,
                    &authorization,
                    &active_client_digest,
                    &active,
                    None,
                    started_at,
                )
                .await
                .unwrap(),
            PushRegistrationHandoffIntentWrite::Created(_)
        ));
        let revoked: PushRegistrationHandoffRequestBody = serde_json::from_value(json!({
            "registration_id": active.registration_id(),
            "push_target_id": active.push_target_id(),
            "device_id": active.device_id(),
            "state": "revoked"
        }))
        .unwrap();
        let receipt = receipt_for(
            &active,
            &source,
            &destination,
            started_at + chrono::Duration::seconds(1),
        );
        let barrier = Arc::new(Barrier::new(3));

        let revoke_task = {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let source = source.clone();
            let route = route.clone();
            let authorization = authorization.clone();
            let revoked = revoked.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .ensure_desired_intent(
                        &source,
                        &route,
                        &authorization,
                        &client_input_digest('2'),
                        &revoked,
                        None,
                        started_at + chrono::Duration::seconds(2),
                    )
                    .await
            })
        };
        let receipt_task = {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let source = source.clone();
            let registration_id = active.registration_id().clone();
            let active_digest = active_digest.clone();
            let receipt = receipt.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .commit_verified_receipt(
                        &source,
                        &registration_id,
                        &active_digest,
                        &receipt,
                        started_at + chrono::Duration::seconds(2),
                    )
                    .await
            })
        };
        barrier.wait().await;
        assert!(matches!(
            revoke_task.await.unwrap().unwrap(),
            PushRegistrationHandoffIntentWrite::AdvancedToRevoked(_)
        ));
        let concurrent_receipt = receipt_task.await.unwrap();
        assert!(
            concurrent_receipt.is_ok()
                || matches!(concurrent_receipt, Err(PersistenceError::Conflict(_)))
        );

        let stored = store
            .get_intent(&source, active.registration_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.desired_state, PushRegistrationHandoffState::Revoked);
        assert_eq!(
            stored.status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );
        assert!(stored.receipt.is_none());
        assert!(matches!(
            store
                .commit_verified_receipt(
                    &source,
                    active.registration_id(),
                    &active_digest,
                    &receipt,
                    started_at + chrono::Duration::seconds(3),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        assert!(matches!(
            store
                .ensure_desired_intent(
                    &source,
                    &route,
                    &authorization,
                    &client_input_digest('2'),
                    &revoked,
                    None,
                    started_at + chrono::Duration::seconds(4),
                )
                .await
                .unwrap(),
            PushRegistrationHandoffIntentWrite::ExactReplay(_)
        ));
        assert!(matches!(
            store
                .ensure_desired_intent(
                    &source,
                    &route,
                    &authorization,
                    &active_client_digest,
                    &active,
                    None,
                    started_at + chrono::Duration::seconds(5),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_local_route_retry_reuses_pending_body_and_preserves_predecessor() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        let source = DidCoreId::new("ak:did_core:web:source.example").unwrap();
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let (route, authorization) = accepted_local_route(&pool, &source, &destination).await;
        let same_client_input = client_input_digest('3');
        let first = active_request_with_id("registration_aaaaaaaaaaaaaaaa", None);
        let retry = active_request_with_id("registration_bbbbbbbbbbbbbbbb", None);
        let started_at = chrono::Utc::now();
        let barrier = Arc::new(Barrier::new(3));

        let first_task = {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let source = source.clone();
            let route = route.clone();
            let authorization = authorization.clone();
            let digest = same_client_input.clone();
            let request = first.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .ensure_desired_intent(
                        &source,
                        &route,
                        &authorization,
                        &digest,
                        &request,
                        None,
                        started_at,
                    )
                    .await
            })
        };
        let retry_task = {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let source = source.clone();
            let route = route.clone();
            let authorization = authorization.clone();
            let digest = same_client_input.clone();
            let request = retry;
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .ensure_desired_intent(
                        &source,
                        &route,
                        &authorization,
                        &digest,
                        &request,
                        None,
                        started_at,
                    )
                    .await
            })
        };
        barrier.wait().await;
        let outcomes = [
            first_task.await.unwrap().unwrap(),
            retry_task.await.unwrap().unwrap(),
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PushRegistrationHandoffIntentWrite::Created(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    PushRegistrationHandoffIntentWrite::ExactReplay(_)
                ))
                .count(),
            1
        );
        let records = outcomes.map(|outcome| match outcome {
            PushRegistrationHandoffIntentWrite::Created(record)
            | PushRegistrationHandoffIntentWrite::ExactReplay(record) => record,
            PushRegistrationHandoffIntentWrite::AdvancedToRevoked(_) => {
                panic!("active retry advanced to revoked")
            }
        });
        assert_eq!(records[0].registration_id, records[1].registration_id);
        assert_eq!(records[0].canonical_request, records[1].canonical_request);
        assert_eq!(records[0].client_input_digest, same_client_input);

        let pending = store
            .lookup_local_route_intent(&source, &route)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.registration_id, records[0].registration_id);
        assert_eq!(
            pending.status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );

        let successor_input = client_input_digest('4');
        let successor = active_request_with_id(
            "registration_cccccccccccccccc",
            Some(&pending.registration_id),
        );
        assert!(matches!(
            store
                .ensure_desired_intent(
                    &source,
                    &route,
                    &authorization,
                    &successor_input,
                    &successor,
                    None,
                    started_at + chrono::Duration::seconds(1),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));

        let pending_request = pending.request().unwrap();
        let receipt = receipt_for(
            &pending_request,
            &source,
            &destination,
            started_at + chrono::Duration::seconds(2),
        );
        store
            .commit_verified_receipt(
                &source,
                &pending.registration_id,
                &pending.request_digest,
                &receipt,
                started_at + chrono::Duration::seconds(2),
            )
            .await
            .unwrap();
        let predecessor = store
            .lookup_local_route_intent(&source, &route)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(predecessor.registration_id, pending.registration_id);
        assert_eq!(
            predecessor.status,
            PushRegistrationHandoffIntentStatus::ReceiptVerified
        );

        assert!(matches!(
            store
                .ensure_desired_intent(
                    &source,
                    &route,
                    &authorization,
                    &successor_input,
                    &successor,
                    None,
                    started_at + chrono::Duration::seconds(3),
                )
                .await
                .unwrap(),
            PushRegistrationHandoffIntentWrite::Created(_)
        ));
        let current = store
            .lookup_local_route_intent(&source, &route)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&current.registration_id, successor.registration_id());
        assert_eq!(
            current.status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );
        let retained = store
            .get_intent(&source, &predecessor.registration_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            retained.status,
            PushRegistrationHandoffIntentStatus::ReceiptVerified
        );
    }

    #[tokio::test]
    async fn verified_receipt_and_local_route_replace_are_one_uow() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let fixture = PcrGenesisFixture::new(did_web_station(&station_id));
        let source = &fixture.history;
        seed_account(&pool, &source.account).await;
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
                .bind::<Text, _>(station_id.as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let authorization = fixture
            .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
            .await
            .expect("accepted PCR genesis");
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route = local_route_for_account(
            source.account.clone(),
            source.founding_device_id.clone(),
            &destination,
        );
        let request = active_request_for_device(
            "registration_dddddddddddddddd",
            &source.founding_device_id,
            "ak:pseudonym:push:lg8aqJ2eJjms1GQpkzloxGn8F802f8RfmfmfsC85eRo",
            "provider-token",
        );
        let registration = local_registration(&source.account, &request);
        let push_store = PgPushDeviceStore { pool: pool.clone() };
        let mut predecessor = registration.clone();
        predecessor.registration_id =
            arkret_wire::OpaqueLocalId::new("push_registration:predecessor").unwrap();
        predecessor.push_target_id =
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8"
                .parse()
                .unwrap();
        predecessor.salt_epoch_id = "ak.push.salt_epoch.41".to_owned();
        push_store
            .register(&authorization, serde_json::to_value(&predecessor).unwrap())
            .await
            .unwrap();
        let before = stored_push_route(&pool, &route).await.unwrap();

        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        let client_digest = client_input_digest('5');
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-09-22T12:00:00.123Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        store
            .ensure_desired_intent(
                &station_id,
                &route,
                &authorization,
                &client_digest,
                &request,
                None,
                started_at,
            )
            .await
            .unwrap();
        let receipt = receipt_for(
            &request,
            &station_id,
            &destination,
            started_at + chrono::Duration::seconds(1),
        );

        let stale_digest = client_input_digest('f');
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    request.registration_id(),
                    &stale_digest,
                    &receipt,
                    &authorization,
                    &registration,
                    None,
                    started_at + chrono::Duration::seconds(2),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        let after_stale = stored_push_route(&pool, &route).await.unwrap();
        assert_eq!(after_stale.payload, before.payload);
        assert_eq!(after_stale.updated_at, before.updated_at);

        let mut wrong_receipt = receipt.clone();
        wrong_receipt.destination_gateway_id =
            DidCoreId::new("ak:did_core:web:wrong-gateway.example").unwrap();
        assert!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    request.registration_id(),
                    &request.request_digest().unwrap(),
                    &wrong_receipt,
                    &authorization,
                    &registration,
                    None,
                    started_at + chrono::Duration::seconds(2),
                )
                .await
                .is_err()
        );
        let after_wrong_receipt = stored_push_route(&pool, &route).await.unwrap();
        assert_eq!(after_wrong_receipt.payload, before.payload);
        assert_eq!(after_wrong_receipt.updated_at, before.updated_at);
        let mut wrong_local_route = registration.clone();
        wrong_local_route.push_route_id = "other.app".to_owned();
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    request.registration_id(),
                    &request.request_digest().unwrap(),
                    &receipt,
                    &authorization,
                    &wrong_local_route,
                    None,
                    started_at + chrono::Duration::seconds(2),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        let after_wrong_route = stored_push_route(&pool, &route).await.unwrap();
        assert_eq!(after_wrong_route.payload, before.payload);
        assert_eq!(after_wrong_route.updated_at, before.updated_at);
        assert_eq!(
            store
                .get_intent(&station_id, request.registration_id())
                .await
                .unwrap()
                .unwrap()
                .status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );

        let stored = store
            .commit_verified_active_receipt_and_push_route(
                &station_id,
                &route,
                request.registration_id(),
                &request.request_digest().unwrap(),
                &receipt,
                &authorization,
                &registration,
                None,
                started_at + chrono::Duration::seconds(3),
            )
            .await
            .unwrap();
        assert!(matches!(
            stored,
            PushRegistrationHandoffReceiptWrite::Stored(_)
        ));
        let installed = stored_push_route(&pool, &route).await.unwrap();
        let installed_registration: PushRegistrationRecord =
            serde_json::from_value(installed.payload.clone()).unwrap();
        assert_eq!(
            installed_registration.registration_id.as_str(),
            request.registration_id().as_str()
        );
        assert_eq!(installed_registration.retained_push_targets.len(), 1);
        assert_eq!(
            installed_registration.retained_push_targets[0].push_target_id,
            predecessor.push_target_id
        );
        assert_eq!(
            store
                .get_intent(&station_id, request.registration_id())
                .await
                .unwrap()
                .unwrap()
                .status,
            PushRegistrationHandoffIntentStatus::ReceiptVerified
        );

        let replay = store
            .commit_verified_active_receipt_and_push_route(
                &station_id,
                &route,
                request.registration_id(),
                &request.request_digest().unwrap(),
                &receipt,
                &authorization,
                &registration,
                None,
                started_at + chrono::Duration::seconds(4),
            )
            .await
            .unwrap();
        assert!(matches!(
            replay,
            PushRegistrationHandoffReceiptWrite::ExactReplay(_)
        ));
        let after_replay = stored_push_route(&pool, &route).await.unwrap();
        assert_eq!(after_replay.payload, installed.payload);
        assert_eq!(after_replay.updated_at, installed.updated_at);

        let successor = active_request_for_device(
            "registration_eeeeeeeeeeeeeeee",
            &source.founding_device_id,
            "ak:pseudonym:push:7EMHE3J_lA1FENBqXW-mmf4Ku3gfVeCu5N73ThBrOEg",
            "replacement-token",
        );
        let successor_registration = local_registration(&source.account, &successor);
        store
            .ensure_desired_intent(
                &station_id,
                &route,
                &authorization,
                &client_input_digest('6'),
                &successor,
                None,
                started_at + chrono::Duration::seconds(5),
            )
            .await
            .unwrap();
        PgDeviceRevocationStore { pool: pool.clone() }
            .commit_revocation(&coland_storage::DeviceRevocationTransition {
                selector: authorization.clone(),
                revoke_ref: authorization.authorization_ref.clone(),
                committed_at: started_at + chrono::Duration::seconds(6),
            })
            .await
            .unwrap();
        let successor_receipt = receipt_for(
            &successor,
            &station_id,
            &destination,
            started_at + chrono::Duration::seconds(7),
        );
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    successor.registration_id(),
                    &successor.request_digest().unwrap(),
                    &successor_receipt,
                    &authorization,
                    &successor_registration,
                    None,
                    started_at + chrono::Duration::seconds(8),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        assert!(stored_push_route(&pool, &route).await.is_none());
        let successor_after_revoke = store
            .get_intent(&station_id, successor.registration_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            successor_after_revoke.status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );
        assert_eq!(
            successor_after_revoke.desired_state,
            PushRegistrationHandoffState::Revoked
        );
    }

    #[tokio::test]
    async fn public_unregistration_filters_routes_and_retains_exact_revoke_outbox() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let fixture = PcrGenesisFixture::new(did_web_station(&station_id));
        let source = &fixture.history;
        seed_account(&pool, &source.account).await;
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
                .bind::<Text, _>(station_id.as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let authorization = fixture
            .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
            .await
            .expect("accepted PCR genesis");
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route_a = local_route_for_account(
            source.account.clone(),
            source.founding_device_id.clone(),
            &destination,
        );
        let mut route_b = route_a.clone();
        route_b.push_route_id = "com.example.voip".to_owned();
        let request_a = active_request_for_route(
            "registration_1111111111111111",
            &source.founding_device_id,
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "provider-token-a",
            "com.example.app",
        );
        let request_b = active_request_for_route(
            "registration_2222222222222222",
            &source.founding_device_id,
            "ak:pseudonym:push:7EMHE3J_lA1FENBqXW-mmf4Ku3gfVeCu5N73ThBrOEg",
            "provider-token-b",
            "com.example.voip",
        );
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-09-23T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        install_public_route(
            &store,
            &station_id,
            &route_a,
            &authorization,
            &request_a,
            &client_input_digest('a'),
            started_at,
        )
        .await;
        install_public_route(
            &store,
            &station_id,
            &route_b,
            &authorization,
            &request_b,
            &client_input_digest('b'),
            started_at + chrono::Duration::seconds(1),
        )
        .await;

        let successor = active_request_for_route_superseding(
            "registration_aaaaaaaaaaaaaaaa",
            &source.founding_device_id,
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "provider-token-a",
            "com.example.app",
            Some(request_a.registration_id()),
        );
        store
            .ensure_desired_intent(
                &station_id,
                &route_a,
                &authorization,
                &client_input_digest('d'),
                &successor,
                None,
                started_at + chrono::Duration::seconds(2),
            )
            .await
            .unwrap();
        let other_destination = DidCoreId::new("ak:did_core:web:gateway-two.example").unwrap();
        let mut other_gateway_route = route_a.clone();
        other_gateway_route.destination_gateway_id = other_destination;
        let other_gateway_pending = active_request_for_route(
            "registration_bbbbbbbbbbbbbbbb",
            &source.founding_device_id,
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "provider-token-a",
            "com.example.app",
        );
        store
            .ensure_desired_intent(
                &station_id,
                &other_gateway_route,
                &authorization,
                &client_input_digest('e'),
                &other_gateway_pending,
                None,
                started_at + chrono::Duration::seconds(3),
            )
            .await
            .unwrap();

        let revoked = store
            .begin_public_push_unregistration(
                &source.account,
                &source.founding_device_id,
                Some("provider-token-a"),
                Some("com.example.app"),
                started_at + chrono::Duration::seconds(4),
            )
            .await
            .unwrap();
        assert_eq!(revoked.len(), 3);
        assert!(revoked.iter().all(|record| {
            record.desired_state == PushRegistrationHandoffState::Revoked
                && record.device_authorization == authorization
        }));
        assert!(stored_push_route(&pool, &route_a).await.is_none());
        assert!(stored_push_route(&pool, &route_b).await.is_some());

        let due = store
            .list_awaiting_revoked_intents(&station_id, None, 10)
            .await
            .unwrap();
        let first_page = store
            .list_awaiting_revoked_intents(&station_id, None, 1)
            .await
            .unwrap();
        assert_eq!(first_page.len(), 1);
        let cursor = PushRegistrationHandoffRetryCursor::after(&first_page[0]);
        let next_page = store
            .list_awaiting_revoked_intents(&station_id, Some(&cursor), 10)
            .await
            .unwrap();
        assert_eq!(next_page.len(), due.len() - 1);
        assert!(next_page.iter().all(|record| {
            record.updated_at > cursor.updated_at
                || (record.updated_at == cursor.updated_at
                    && record.registration_id > cursor.registration_id)
        }));
        let mut due_ids = due
            .iter()
            .map(|record| record.registration_id.as_str())
            .collect::<Vec<_>>();
        due_ids.sort_unstable();
        assert_eq!(
            due_ids,
            vec![
                request_a.registration_id().as_str(),
                successor.registration_id().as_str(),
                other_gateway_pending.registration_id().as_str(),
            ]
        );
        let retry = store
            .begin_public_push_unregistration(
                &source.account,
                &source.founding_device_id,
                Some("provider-token-a"),
                Some("com.example.app"),
                started_at + chrono::Duration::seconds(5),
            )
            .await
            .unwrap();
        assert_eq!(retry.len(), revoked.len());
        assert!(retry.iter().all(|replayed| {
            revoked.iter().any(|first| {
                first.registration_id == replayed.registration_id
                    && first.canonical_request == replayed.canonical_request
            })
        }));
        let active_receipt = receipt_for(
            &request_a,
            &station_id,
            &destination,
            started_at + chrono::Duration::seconds(6),
        );
        assert!(matches!(
            store
                .commit_verified_receipt(
                    &station_id,
                    request_a.registration_id(),
                    &request_a.request_digest().unwrap(),
                    &active_receipt,
                    started_at + chrono::Duration::seconds(7),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        let successor_receipt = receipt_for(
            &successor,
            &station_id,
            &destination,
            started_at + chrono::Duration::seconds(6),
        );
        let successor_registration = local_registration(&source.account, &successor);
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route_a,
                    successor.registration_id(),
                    &successor.request_digest().unwrap(),
                    &successor_receipt,
                    &authorization,
                    &successor_registration,
                    None,
                    started_at + chrono::Duration::seconds(7),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        let other_gateway_receipt = receipt_for(
            &other_gateway_pending,
            &station_id,
            &other_gateway_route.destination_gateway_id,
            started_at + chrono::Duration::seconds(6),
        );
        let other_gateway_registration =
            local_registration(&source.account, &other_gateway_pending);
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &other_gateway_route,
                    other_gateway_pending.registration_id(),
                    &other_gateway_pending.request_digest().unwrap(),
                    &other_gateway_receipt,
                    &authorization,
                    &other_gateway_registration,
                    None,
                    started_at + chrono::Duration::seconds(7),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        assert!(stored_push_route(&pool, &route_a).await.is_none());
        assert!(
            stored_push_route(&pool, &other_gateway_route)
                .await
                .is_none()
        );

        let predecessor_revoke = retry
            .iter()
            .find(|record| record.registration_id == *request_a.registration_id())
            .unwrap();
        let predecessor_revoke_request = predecessor_revoke.request().unwrap();
        let predecessor_revoke_receipt = receipt_for(
            &predecessor_revoke_request,
            &station_id,
            &predecessor_revoke.destination_gateway_id,
            started_at + chrono::Duration::seconds(8),
        );
        store
            .commit_verified_receipt(
                &station_id,
                &predecessor_revoke.registration_id,
                &predecessor_revoke.request_digest,
                &predecessor_revoke_receipt,
                started_at + chrono::Duration::seconds(8),
            )
            .await
            .unwrap();
        let remaining = store
            .begin_public_push_unregistration(
                &source.account,
                &source.founding_device_id,
                Some("provider-token-a"),
                Some("com.example.app"),
                started_at + chrono::Duration::seconds(9),
            )
            .await
            .unwrap();
        assert_eq!(
            remaining.len(),
            2,
            "confirmed revokes leave only retryable peers"
        );
        for record in remaining {
            let request = record.request().unwrap();
            let receipt = receipt_for(
                &request,
                &station_id,
                &record.destination_gateway_id,
                started_at + chrono::Duration::seconds(10),
            );
            store
                .commit_verified_receipt(
                    &station_id,
                    &record.registration_id,
                    &record.request_digest,
                    &receipt,
                    started_at + chrono::Duration::seconds(10),
                )
                .await
                .unwrap();
        }
        assert!(
            store
                .begin_public_push_unregistration(
                    &source.account,
                    &source.founding_device_id,
                    Some("provider-token-a"),
                    Some("com.example.app"),
                    started_at + chrono::Duration::seconds(11),
                )
                .await
                .unwrap()
                .is_empty(),
            "a fully confirmed exact retry has zero remaining public work"
        );

        let mut wrong_generation = authorization.clone();
        wrong_generation.authorization_ref.stream_position += 1;
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("UPDATE push_devices SET device_authorization=$2 WHERE id=$1")
                .bind::<Text, _>(request_b.registration_id().as_str())
                .bind::<Jsonb, _>(serde_json::to_value(&wrong_generation).unwrap())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        assert!(matches!(
            store
                .begin_public_push_unregistration(
                    &source.account,
                    &source.founding_device_id,
                    Some("provider-token-b"),
                    Some("com.example.voip"),
                    started_at + chrono::Duration::seconds(12),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        assert!(stored_push_route(&pool, &route_b).await.is_some());
        assert_eq!(
            store
                .get_intent(&station_id, request_b.registration_id())
                .await
                .unwrap()
                .unwrap()
                .desired_state,
            PushRegistrationHandoffState::Active
        );
    }

    #[tokio::test]
    async fn concurrent_public_unregistration_advances_once_and_replays_exact_revoke() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let fixture = PcrGenesisFixture::new(did_web_station(&station_id));
        let source = &fixture.history;
        seed_account(&pool, &source.account).await;
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
                .bind::<Text, _>(station_id.as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let authorization = fixture
            .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
            .await
            .expect("accepted PCR genesis");
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route = local_route_for_account(
            source.account.clone(),
            source.founding_device_id.clone(),
            &destination,
        );
        let request = active_request_for_device(
            "registration_3333333333333333",
            &source.founding_device_id,
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "provider-token",
        );
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-09-23T00:10:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        install_public_route(
            &store,
            &station_id,
            &route,
            &authorization,
            &request,
            &client_input_digest('c'),
            started_at,
        )
        .await;
        let barrier = Arc::new(Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let account = source.account.clone();
            let device_id = source.founding_device_id.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .begin_public_push_unregistration(
                        &account,
                        &device_id,
                        None,
                        None,
                        started_at + chrono::Duration::seconds(1),
                    )
                    .await
            }));
        }
        barrier.wait().await;
        let first = tasks.remove(0).await.unwrap().unwrap();
        let second = tasks.remove(0).await.unwrap().unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].registration_id, second[0].registration_id);
        assert_eq!(first[0].canonical_request, second[0].canonical_request);
        assert!(stored_push_route(&pool, &route).await.is_none());
        let due = store
            .list_awaiting_revoked_intents(&station_id, None, 10)
            .await
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].registration_id, *request.registration_id());
        assert_eq!(
            due[0].request().unwrap().state(),
            PushRegistrationHandoffState::Revoked
        );
    }

    #[tokio::test]
    async fn concurrent_pending_create_linearizes_before_or_after_unregistration() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let (route, authorization) = accepted_local_route(&pool, &station_id, &destination).await;
        let existing = active_request_with_id("registration_cccccccccccccccc", None);
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-09-23T00:15:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        store
            .ensure_desired_intent(
                &station_id,
                &route,
                &authorization,
                &client_input_digest('f'),
                &existing,
                None,
                started_at,
            )
            .await
            .unwrap();

        let second_destination = DidCoreId::new("ak:did_core:web:gateway-two.example").unwrap();
        let mut raced_route = route.clone();
        raced_route.destination_gateway_id = second_destination;
        let raced = active_request_with_id("registration_dddddddddddddddd", None);
        let barrier = Arc::new(Barrier::new(3));
        let unregister_task = {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let account_id = route.account_id.clone();
            let device_id = route.device_id.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .begin_public_push_unregistration(
                        &account_id,
                        &device_id,
                        None,
                        None,
                        started_at + chrono::Duration::seconds(1),
                    )
                    .await
            })
        };
        let create_task = {
            let barrier = barrier.clone();
            let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
            let station_id = station_id.clone();
            let authorization = authorization.clone();
            let raced_route = raced_route.clone();
            let raced = raced.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .ensure_desired_intent(
                        &station_id,
                        &raced_route,
                        &authorization,
                        &client_input_digest('9'),
                        &raced,
                        None,
                        started_at + chrono::Duration::seconds(1),
                    )
                    .await
            })
        };
        barrier.wait().await;
        let revoked = unregister_task.await.unwrap().unwrap();
        assert!(matches!(
            create_task.await.unwrap().unwrap(),
            PushRegistrationHandoffIntentWrite::Created(_)
        ));

        let existing_after = store
            .get_intent(&station_id, existing.registration_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            existing_after.desired_state,
            PushRegistrationHandoffState::Revoked,
            "an intent durable before the account/device lock is always terminated"
        );
        let raced_after = store
            .get_intent(&station_id, raced.registration_id())
            .await
            .unwrap()
            .unwrap();
        let raced_was_revoked = revoked
            .iter()
            .any(|record| record.registration_id == *raced.registration_id());
        assert_eq!(
            raced_after.desired_state == PushRegistrationHandoffState::Revoked,
            raced_was_revoked,
            "the raced create is either included before the linearization point or remains a later explicit registration"
        );
    }

    #[tokio::test]
    async fn verified_replay_requires_the_exact_live_gate_and_local_route() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let fixture = PcrGenesisFixture::new(did_web_station(&station_id));
        let source = &fixture.history;
        seed_account(&pool, &source.account).await;
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
                .bind::<Text, _>(station_id.as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let authorization = fixture
            .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
            .await
            .expect("accepted PCR genesis");
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route = local_route_for_account(
            source.account.clone(),
            source.founding_device_id.clone(),
            &destination,
        );
        let request = active_request_for_device(
            "registration_4444444444444444",
            &source.founding_device_id,
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "provider-token",
        );
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-09-23T00:20:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        install_public_route(
            &store,
            &station_id,
            &route,
            &authorization,
            &request,
            &client_input_digest('d'),
            started_at,
        )
        .await;
        let receipt = receipt_for(
            &request,
            &station_id,
            &destination,
            started_at + chrono::Duration::milliseconds(1),
        );
        let registration = local_registration(&source.account, &request);
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("DELETE FROM push_devices WHERE id=$1")
                .bind::<Text, _>(request.registration_id().as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    request.registration_id(),
                    &request.request_digest().unwrap(),
                    &receipt,
                    &authorization,
                    &registration,
                    None,
                    started_at + chrono::Duration::seconds(1),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));

        PgPushDeviceStore { pool: pool.clone() }
            .register(&authorization, serde_json::to_value(&registration).unwrap())
            .await
            .unwrap();
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("UPDATE push_devices SET public_handoff=TRUE WHERE id=$1")
                .bind::<Text, _>(request.registration_id().as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    request.registration_id(),
                    &request.request_digest().unwrap(),
                    &receipt,
                    &authorization,
                    &registration,
                    None,
                    started_at + chrono::Duration::seconds(2),
                )
                .await
                .unwrap(),
            PushRegistrationHandoffReceiptWrite::ExactReplay(_)
        ));
        let mut local_only = registration.clone();
        local_only.registration_id =
            arkret_wire::OpaqueLocalId::new("registration_6666666666666666").unwrap();
        local_only.push_route_id = "local-only-route".to_owned();
        local_only.push_key =
            arkret_models_integration::PushKey::new("local-provider-token").unwrap();
        local_only.push_target_id = arkret_identifiers::PushTargetId::new(
            "ak:pseudonym:push:7EMHE3J_lA1FENBqXW-mmf4Ku3gfVeCu5N73ThBrOEg",
        )
        .unwrap();
        let mut local_only_locator = route.clone();
        local_only_locator.push_route_id = local_only.push_route_id.clone();
        PgPushDeviceStore { pool: pool.clone() }
            .register(&authorization, serde_json::to_value(&local_only).unwrap())
            .await
            .unwrap();
        PgDeviceRevocationStore { pool: pool.clone() }
            .commit_revocation(&coland_storage::DeviceRevocationTransition {
                selector: authorization.clone(),
                revoke_ref: authorization.authorization_ref.clone(),
                committed_at: started_at + chrono::Duration::seconds(3),
            })
            .await
            .unwrap();
        assert!(stored_push_route(&pool, &route).await.is_none());
        assert!(
            stored_push_route(&pool, &local_only_locator)
                .await
                .is_some(),
            "a local-only route is not public merely because its id has public-looking syntax"
        );
        let revoked = store
            .get_intent(&station_id, request.registration_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(revoked.desired_state, PushRegistrationHandoffState::Revoked);
        assert_eq!(
            revoked.status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );
        assert!(matches!(
            revoked.request().unwrap(),
            PushRegistrationHandoffRequestBody::Revoked {
                registration_id,
                push_target_id,
                device_id,
            } if registration_id == *request.registration_id()
                && push_target_id == registration.push_target_id
                && device_id == source.founding_device_id
        ));
        let durable_revoke = revoked.canonical_request.clone();
        assert_eq!(
            PgDeviceRevocationStore { pool: pool.clone() }
                .commit_revocation(&coland_storage::DeviceRevocationTransition {
                    selector: authorization.clone(),
                    revoke_ref: authorization.authorization_ref.clone(),
                    committed_at: started_at + chrono::Duration::seconds(3),
                })
                .await
                .unwrap(),
            coland_storage::DeviceRevocationTransitionDecision::Duplicate
        );
        assert_eq!(
            store
                .get_intent(&station_id, request.registration_id())
                .await
                .unwrap()
                .unwrap()
                .canonical_request,
            durable_revoke,
            "an exact revocation replay keeps the original Gateway tombstone bytes"
        );
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    request.registration_id(),
                    &request.request_digest().unwrap(),
                    &receipt,
                    &authorization,
                    &registration,
                    None,
                    started_at + chrono::Duration::seconds(4),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        assert!(stored_push_route(&pool, &route).await.is_none());
    }

    #[tokio::test]
    async fn public_handoff_expiry_is_inclusive_and_keeps_local_only_routes() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let fixture = PcrGenesisFixture::new(did_web_station(&station_id));
        let source = &fixture.history;
        seed_account(&pool, &source.account).await;
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
                .bind::<Text, _>(station_id.as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let authorization = fixture
            .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
            .await
            .expect("accepted PCR genesis");
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route = local_route_for_account(
            source.account.clone(),
            source.founding_device_id.clone(),
            &destination,
        );
        let expiry = chrono::DateTime::parse_from_rfc3339("2026-09-23T01:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let request = active_request_expiring_at(
            "registration_7777777777777777",
            &source.founding_device_id,
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "provider-token",
            expiry,
        );
        let started_at = expiry - chrono::Duration::minutes(10);
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        install_public_route(
            &store,
            &station_id,
            &route,
            &authorization,
            &request,
            &client_input_digest('f'),
            started_at,
        )
        .await;
        let receipt = receipt_for(
            &request,
            &station_id,
            &destination,
            started_at + chrono::Duration::milliseconds(1),
        );
        let registration = local_registration(&source.account, &request);

        let mut local_only = registration.clone();
        local_only.registration_id =
            arkret_wire::OpaqueLocalId::new("registration_8888888888888888").unwrap();
        local_only.push_route_id = "local-expiring-route".to_owned();
        local_only.push_key =
            arkret_models_integration::PushKey::new("local-provider-token").unwrap();
        let mut local_only_locator = route.clone();
        local_only_locator.push_route_id = local_only.push_route_id.clone();
        PgPushDeviceStore { pool: pool.clone() }
            .register(&authorization, serde_json::to_value(&local_only).unwrap())
            .await
            .unwrap();

        assert!(
            store
                .expire_public_push_registrations(
                    &station_id,
                    expiry - chrono::Duration::milliseconds(1),
                    None,
                    64,
                )
                .await
                .unwrap()
                .expired
                .is_empty()
        );
        assert!(stored_push_route(&pool, &route).await.is_some());
        let expired = store
            .expire_public_push_registrations(&station_id, expiry, None, 64)
            .await
            .unwrap();
        assert_eq!(expired.expired.len(), 1);
        assert_eq!(
            expired.expired[0].desired_state,
            PushRegistrationHandoffState::Revoked
        );
        assert_eq!(
            expired.expired[0].status,
            PushRegistrationHandoffIntentStatus::AwaitingReceipt
        );
        assert!(stored_push_route(&pool, &route).await.is_none());
        assert!(
            stored_push_route(&pool, &local_only_locator)
                .await
                .is_some()
        );
        assert!(matches!(
            store
                .commit_verified_active_receipt_and_push_route(
                    &station_id,
                    &route,
                    request.registration_id(),
                    &request.request_digest().unwrap(),
                    &receipt,
                    &authorization,
                    &registration,
                    None,
                    expiry + chrono::Duration::milliseconds(1),
                )
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        assert!(stored_push_route(&pool, &route).await.is_none());
        assert!(
            store
                .expire_public_push_registrations(&station_id, expiry, None, 64)
                .await
                .unwrap()
                .expired
                .is_empty(),
            "an exact expiry replay reuses the already durable tombstone"
        );
    }

    #[tokio::test]
    async fn expiry_cursor_advances_past_a_conflicting_first_row_to_the_sixty_fifth() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let fixture = PcrGenesisFixture::new(did_web_station(&station_id));
        let source = &fixture.history;
        seed_account(&pool, &source.account).await;
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
                .bind::<Text, _>(station_id.as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let authorization = fixture
            .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
            .await
            .expect("accepted PCR genesis");
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let expiry = chrono::DateTime::parse_from_rfc3339("2026-09-23T02:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        let mut requests = Vec::new();
        for index in 0..65 {
            let registration_id = format!("registration_{index:016x}");
            let request = active_request_expiring_at(
                &registration_id,
                &source.founding_device_id,
                "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
                "provider-token",
                expiry,
            );
            let mut route = local_route_for_account(
                source.account.clone(),
                source.founding_device_id.clone(),
                &destination,
            );
            route.push_route_id = format!("expiry-route-{index:02}");
            store
                .ensure_desired_intent(
                    &station_id,
                    &route,
                    &authorization,
                    &client_input_digest('e'),
                    &request,
                    None,
                    expiry - chrono::Duration::minutes(1),
                )
                .await
                .unwrap();
            requests.push((request, route));
        }

        // A local-only route with the same registration id makes the first
        // expiry candidate fail closed without corrupting its durable intent.
        let mut collision = local_registration(&source.account, &requests[0].0);
        collision.push_route_id = requests[0].1.push_route_id.clone();
        PgPushDeviceStore { pool: pool.clone() }
            .register(&authorization, serde_json::to_value(collision).unwrap())
            .await
            .unwrap();

        let first = store
            .expire_public_push_registrations(&station_id, expiry, None, 64)
            .await
            .unwrap();
        assert_eq!(first.scanned, 64);
        assert_eq!(first.failed, 1);
        assert_eq!(first.expired.len(), 63);
        let cursor = first.next_cursor.expect("a full page advances its cursor");

        let second = store
            .expire_public_push_registrations(&station_id, expiry, Some(&cursor), 64)
            .await
            .unwrap();
        assert_eq!(second.scanned, 1);
        assert_eq!(second.failed, 0);
        assert_eq!(second.expired.len(), 1);
        assert_eq!(
            second.expired[0].registration_id,
            requests[64].0.registration_id().clone()
        );
        assert_eq!(
            store
                .get_intent(&station_id, requests[0].0.registration_id())
                .await
                .unwrap()
                .unwrap()
                .desired_state,
            PushRegistrationHandoffState::Active,
            "the conflicting row remains fail-closed for a later operator-visible retry"
        );
    }

    #[tokio::test]
    async fn device_revocation_rolls_back_when_a_public_route_lost_its_handoff() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let station_id = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let fixture = PcrGenesisFixture::new(did_web_station(&station_id));
        let source = &fixture.history;
        seed_account(&pool, &source.account).await;
        {
            let mut conn = pool.get().await.unwrap();
            sql_query("INSERT INTO device_inventory_station(singleton,station_id) VALUES(TRUE,$1)")
                .bind::<Text, _>(station_id.as_str())
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        let authorization = fixture
            .admit_founding_device(&PgPersistenceStore::new(pool.clone()))
            .await
            .expect("accepted PCR genesis");
        let destination = DidCoreId::new("ak:did_core:web:gateway.example").unwrap();
        let route = local_route_for_account(
            source.account.clone(),
            source.founding_device_id.clone(),
            &destination,
        );
        let request = active_request_for_device(
            "registration_5555555555555555",
            &source.founding_device_id,
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "provider-token",
        );
        let started_at = chrono::DateTime::parse_from_rfc3339("2026-09-23T00:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let store = PgPushRegistrationHandoffStore { pool: pool.clone() };
        install_public_route(
            &store,
            &station_id,
            &route,
            &authorization,
            &request,
            &client_input_digest('e'),
            started_at,
        )
        .await;
        {
            let mut conn = pool.get().await.unwrap();
            sql_query(
                "DELETE FROM push_registration_handoff_intents \
                 WHERE source_station_id=$1 AND registration_id=$2",
            )
            .bind::<Text, _>(&station_id)
            .bind::<Text, _>(request.registration_id().as_str())
            .execute(&mut *conn)
            .await
            .unwrap();
        }
        // The revocation is refused before its reference is recorded, so any
        // committed reference of this PCR serves as the attempted revoke.
        let transition = coland_storage::DeviceRevocationTransition {
            revoke_ref: authorization.authorization_ref.clone(),
            selector: authorization,
            committed_at: started_at + chrono::Duration::seconds(1),
        };
        assert!(matches!(
            PgDeviceRevocationStore { pool: pool.clone() }
                .commit_revocation(&transition)
                .await,
            Err(PersistenceError::Conflict(_))
        ));
        assert!(
            PgDeviceRevocationStore { pool: pool.clone() }
                .target_for_event(&transition.revoke_ref.event_id)
                .await
                .unwrap()
                .is_none(),
            "the accepted revocation target must roll back with the missing tombstone"
        );
        assert!(stored_push_route(&pool, &route).await.is_some());
    }
}
