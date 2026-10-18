//! Scope-bound native recipient pages and exact, post-delivery acknowledgements.
use arkret_models_collaboration::device_messages::{DeviceMessagesGetOutcome, RecipientDelivery};
use arkret_models_crypto::{MlsCommitPayload, PeerKeyPackagesClaimOutcome};
use arkret_wire::{ActorId, ScopeRef};
use coland_storage::{
    AccountContentDeliveryGuard, AppletDeviceQueueAck, AppletDeviceQueuePage,
    AppletDeviceQueueRead, AppletManagedDeviceAuthority, AppletManagedDeviceScopeGuard,
    PersistedKeyPackageClaimState, SyncCursorRecord,
};
use diesel::sql_types::Array;
use serde_json::json;

use super::*;

fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}
fn cursor_error(code: &str, detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{code}: {detail}"))
}
#[derive(QueryableByName)]
struct QueueRow {
    #[diesel(sql_type=BigInt)]
    position: i64,
    #[diesel(sql_type=Jsonb)]
    delivery_json: Value,
}
#[derive(QueryableByName)]
struct MaterialRow {
    #[diesel(sql_type=Text)]
    source_id: String,
    #[diesel(sql_type=Text)]
    claim_request_id: String,
    #[diesel(sql_type=Text)]
    request_digest: String,
    #[diesel(sql_type=Text)]
    key_package_use: String,
    #[diesel(sql_type=Nullable<Text>)]
    keypackage_id: Option<String>,
    #[diesel(sql_type=Jsonb)]
    outcome: Value,
    #[diesel(sql_type=Text)]
    state: String,
    #[diesel(sql_type=BigInt)]
    expires_at: i64,
    #[diesel(sql_type=Nullable<BigInt>)]
    claim_expires_at_unix_ms: Option<i64>,
    #[diesel(sql_type=Text)]
    welcome_id: String,
    #[diesel(sql_type=Text)]
    welcome_digest: String,
    #[diesel(sql_type=Text)]
    commit_event_ref: String,
}
#[derive(QueryableByName)]
struct AckRow {
    #[diesel(sql_type=Text)]
    recipient: String,
    #[diesel(sql_type=Text)]
    device_id: String,
    #[diesel(sql_type=Jsonb)]
    recipient_device_authorization: Value,
    #[diesel(sql_type=Jsonb)]
    effective_scope: Value,
    #[diesel(sql_type=Array<BigInt>)]
    delivered_positions: Vec<i64>,
    #[diesel(sql_type=Timestamptz)]
    expires_at: chrono::DateTime<Utc>,
    #[diesel(sql_type=Nullable<Timestamptz>)]
    consumed_at: Option<chrono::DateTime<Utc>>,
}
struct PendingPage {
    held: Box<crate::account_content_delivery::DeliveryGuard>,
    proof: crate::applet_content_delivery::ReadProof,
    deadline: chrono::DateTime<Utc>,
}
#[async_trait]
impl AccountContentDeliveryGuard for PendingPage {
    fn permits_handoff(&self) -> bool {
        let at = Utc::now();
        at < self.deadline && self.proof.permits_at(at)
    }
    async fn prepare_handoff(&mut self) -> bool {
        if !self.permits_handoff() {
            return false;
        }
        let Ok(remaining) = (self.deadline - Utc::now()).to_std() else {
            return false;
        };
        matches!(
            tokio::time::timeout(
                remaining.min(std::time::Duration::from_secs(5)),
                self.held.probe()
            )
            .await,
            Ok(Ok(()))
        ) && self.permits_handoff()
    }
    async fn finish(self: Box<Self>) -> PersistenceResult<()> {
        self.held.commit().await
    }
}
fn endpoint_binding(endpoint: &AppletManagedDeviceScopeGuard) -> PersistenceResult<Value> {
    // This is an opaque private cursor binding, not another wire endpoint
    // DTO. The existing selector retains full Account/Station/Device and the
    // original authorization; the other typed values pin generation/scope.
    serde_json::to_value((
        &endpoint.authority.selector,
        &endpoint.authority.current_device_generation_ref,
        &endpoint.effective_scope,
    ))
    .map_err(PersistenceError::database)
}
fn subject(authority: &AppletManagedDeviceAuthority) -> PersistenceResult<String> {
    String::from_utf8(
        arkret_canonical::canonical_json_bytes(&authority.account_id)
            .map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)
}
fn cursor_context(
    subject: &str,
    device: Option<String>,
    service: arkret_wire::DidCoreId,
    operation: &str,
    filter: Option<&str>,
    endpoint: Option<Value>,
) -> PersistenceResult<arkret::server::CursorBindingContext> {
    let digest = arkret::server::cursor_filter_digest(
        &json!({"operation":operation,"filter":filter,"target":endpoint}),
    )
    .map_err(PersistenceError::database)?;
    Ok(arkret::server::CursorBindingContext::new(
        subject, device, service, digest,
    ))
}
async fn continuation(
    conn: &mut AsyncPgConnection,
    endpoint: &AppletManagedDeviceScopeGuard,
    token: &str,
) -> PersistenceResult<(i64, SyncCursorRecord)> {
    use arkret::server::{CursorAuthority, CursorAuthorityError, CursorBindingRecord};
    let now = Utc::now().timestamp_millis();
    let purpose = arkret::hlc::CursorPurpose::Stream;
    let cursor =
        arkret::hlc::Cursor::decode_for_purpose_at(token, now, &purpose).map_err(|error| {
            cursor_error(
                if error.error_code() == Some(arkret_wire::ErrorCode::CursorExpired) {
                    "cursor_expired"
                } else {
                    "cursor_integrity_invalid"
                },
                "native queue cursor is invalid",
            )
        })?;
    let stored = crate::sync_cursor::get_in_connection(conn, &cursor.h)
        .await?
        .ok_or_else(|| {
            cursor_error(
                "cursor_integrity_invalid",
                "native queue cursor issuance is absent",
            )
        })?;
    let operation = arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1;
    if stored.session_id.is_some() || stored.positions.is_some() || stored.purpose != operation {
        return Err(cursor_error(
            "cursor_integrity_invalid",
            "native queue cursor has another authority kind",
        ));
    }
    let actual = cursor_context(
        stored
            .binding_subject
            .as_deref()
            .ok_or_else(|| cursor_error("cursor_integrity_invalid", "cursor subject is absent"))?,
        stored.device_id.clone(),
        stored.service_id.clone(),
        &stored.purpose,
        stored.filter_digest.as_deref(),
        stored
            .target
            .as_ref()
            .and_then(|v| v.get("endpoint"))
            .cloned(),
    )?;
    let expected = cursor_context(
        &subject(&endpoint.authority)?,
        Some(endpoint.authority.device_id.to_string()),
        endpoint.authority.account_id.station_id.clone(),
        operation,
        None,
        Some(endpoint_binding(endpoint)?),
    )?;
    let record = CursorBindingRecord {
        handle: stored.handle.clone(),
        context: actual,
        purpose: purpose.clone(),
        positions: Value::Null,
        issued_at_ms: stored.issued_at_ms,
        expires_at_ms: stored.expires_at_ms,
    };
    CursorAuthority::validate_binding(&cursor, &purpose, &expected, Some(&record), now).map_err(
        |error| {
            cursor_error(
                if matches!(error, CursorAuthorityError::Expired) {
                    "cursor_expired"
                } else {
                    "cursor_integrity_invalid"
                },
                "native queue cursor binding changed",
            )
        },
    )?;
    crate::sync_cursor::validate_issuance_inputs(conn, std::slice::from_ref(&stored))
        .await
        .map_err(PgTransactionError::into_persistence)?;
    let position = stored
        .target
        .as_ref()
        .and_then(|v| v.get("queue_position"))
        .and_then(Value::as_i64)
        .filter(|p| *p >= 0)
        .ok_or_else(|| {
            cursor_error(
                "cursor_integrity_invalid",
                "native queue cursor position is absent",
            )
        })?;
    Ok((position, stored))
}
async fn require_device(
    conn: &mut AsyncPgConnection,
    authority: &AppletManagedDeviceAuthority,
    scope: &ScopeRef,
    deadline: chrono::DateTime<Utc>,
) -> PersistenceResult<()> {
    let at = Utc::now();
    let current = crate::boxed_future(|| {
        crate::pcr_applet_device_authority::current_in_connection(
            conn,
            &authority.account_id,
            &authority.device_id,
            at,
        )
    })
    .await
    .map_err(PgTransactionError::into_persistence)?
    .ok_or_else(|| denied("native queue Device is absent"))?;
    if &current != authority
        || !authority.scopes.contains_scope(scope)
        || at >= deadline
        || at >= authority.expires_at
    {
        return Err(denied("native queue Device instance or window changed"));
    }
    Ok(())
}

/// This selects existing material, not a new Add. A consumed claim may still
/// have an unacknowledged Welcome: keep the original retained audit authority.
async fn material_deadline(
    conn: &mut AsyncPgConnection,
    endpoint: &AppletManagedDeviceScopeGuard,
    welcome: &arkret_wire::MlsWelcomeDelivery,
) -> PersistenceResult<chrono::DateTime<Utc>> {
    let authority = &endpoint.authority;
    if welcome.recipient_actor_id != ActorId::account(authority.account_id.clone())
        || welcome.effective_scope != endpoint.effective_scope
        || !matches!(&welcome.recipient_endpoint,arkret_wire::MlsWelcomeRecipientEndpoint::Device{device_id} if device_id==&authority.device_id)
    {
        return Err(denied(
            "native queued delivery has another recipient or scope",
        ));
    }
    welcome
        .validate_shape()
        .map_err(PersistenceError::database)?;
    let row=sql_query("SELECT l.source_id,l.claim_request_id,l.request_digest,l.key_package_use,l.keypackage_id,l.outcome,l.state,l.expires_at,l.claim_expires_at_unix_ms,b.welcome_id,b.welcome_digest,b.commit_event_ref FROM keypackage_claim_welcome_bindings b JOIN peer_keypackage_claims l ON l.source_id=b.source_id AND l.claim_request_id=b.claim_request_id WHERE b.claim_id=$1 FOR SHARE OF l,b NOWAIT")
        .bind::<Text,_>(welcome.keypackage_claim_ref.as_str()).get_result::<MaterialRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||denied("queued Welcome has no original claim binding"))?;
    let outcome: PeerKeyPackagesClaimOutcome =
        serde_json::from_value(row.outcome).map_err(PersistenceError::database)?;
    outcome
        .validate_shape()
        .map_err(PersistenceError::database)?;
    let claim = outcome
        .claims
        .iter()
        .find(|claim| claim.claim_id == welcome.keypackage_claim_ref.as_str())
        .ok_or_else(|| denied("queued Welcome is absent from its original outcome"))?;
    let package = crate::mls::key_package_for_delivery(conn, &claim.keypackage_ref)
        .await?
        .ok_or_else(|| denied("queued Welcome package is unavailable"))?;
    let request = &outcome.claim_receipt.request;
    if row.source_id != outcome.claim_receipt.source_id.as_str()
        || row.claim_request_id != outcome.claim_request_id.as_str()
        || row.request_digest != outcome.claim_receipt.request_digest.as_str()
        || outcome.claim_receipt.destination_id != authority.account_id.station_id
        || row.welcome_id != welcome.welcome_id.as_str()
        || row.welcome_digest
            != welcome
                .durable_receipt_digest()
                .map_err(PersistenceError::database)?
                .as_str()
        || row.commit_event_ref != welcome.commit_event_ref.as_str()
        || row.keypackage_id.as_deref() != Some(package.id.as_str())
        || package.owner_account_id != authority.account_id
        || package.effective_scope.as_ref() != Some(&endpoint.effective_scope)
        || package.device_id.as_deref() != Some(authority.device_id.as_str())
        || package.device_authorize_event_id.as_deref()
            != Some(authority.selector.authorization_ref.event_id.as_str())
        || claim.actor_id.as_account_id() != Some(&authority.account_id)
        || claim.device_id.as_ref() != Some(&authority.device_id)
        || claim.device_authorize_event_id.as_ref()
            != Some(&authority.selector.authorization_ref.event_id)
        || claim.agent_id.is_some()
        || claim.agent_verification_method.is_some()
        || claim.agent_key_authorize_event_id.is_some()
        || claim.keypackage != arkret_canonical::base64url_encode(&package.key_package_bytes)
        || claim.capabilities != package.capabilities
        || claim.last_resort.unwrap_or(false) != package.last_resort
        || request.target_account_id.as_ref() != Some(&authority.account_id)
        || request.intended_realm_id != welcome.realm_id
        || request.mls_group_id
            != endpoint
                .effective_scope
                .canonical_mls_group_id()
                .map_err(PersistenceError::database)?
    {
        return Err(denied(
            "queued Welcome differs from original package and claim",
        ));
    }
    let state = package
        .lifecycle()
        .map_err(PersistenceError::database)?
        .claim_state;
    if matches!(
        state,
        PersistedKeyPackageClaimState::Revoked | PersistedKeyPackageClaimState::Retired
    ) || (matches!(state, PersistedKeyPackageClaimState::Available) && !package.last_resort)
        || Utc::now().timestamp() < package.lifetime_not_before
        || row.key_package_use
            != if package.last_resort {
                "last_resort"
            } else {
                "single_use"
            }
    {
        return Err(denied("queued Welcome package is no longer usable"));
    }
    let mut deadline = chrono::DateTime::from_timestamp(row.expires_at, 0)
        .ok_or_else(|| denied("claim retention is invalid"))?
        .min(
            chrono::DateTime::from_timestamp(package.lifetime_not_after, 0)
                .ok_or_else(|| denied("package lifetime is invalid"))?,
        );
    match row.state.as_str() {
        "claimed" | "last_resort_claimed" => {
            deadline = deadline.min(
                row.claim_expires_at_unix_ms
                    .and_then(chrono::DateTime::from_timestamp_millis)
                    .ok_or_else(|| denied("original claim window is absent"))?,
            );
        }
        "consumed" => {}
        _ => return Err(denied("queued Welcome claim is no longer deliverable")),
    }
    let full = crate::committed_disclosure::accepted_full_event_in_connection(
        conn,
        &welcome.commit_event_ref,
    )
    .await?
    .ok_or_else(|| denied("queued Welcome has no accepted winning Add"))?;
    if full.event.kind != arkret_wire::EventKind::MlsCommit
        || full.event.scope_ref != endpoint.effective_scope
        || full.event.realm_id != welcome.realm_id
        || !crate::boxed_future(|| {
            crate::committed_disclosure::full_event_for_member_in_connection(
                conn,
                &full,
                &welcome.recipient_actor_id,
                Utc::now(),
            )
        })
        .await?
    {
        return Err(denied("queued Welcome has no current history disclosure"));
    }
    let payload: MlsCommitPayload = serde_json::from_value(
        serde_json::to_value(&full.event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    if payload.governance_binding().effective_scope() != &endpoint.effective_scope {
        return Err(denied("queued Welcome Add binds another group scope"));
    }
    if Utc::now() >= deadline {
        return Err(denied("queued Welcome material window ended"));
    }
    Ok(deadline)
}

pub(super) async fn read(
    pool: &PgPool,
    input: AppletDeviceQueueRead<'_>,
) -> PersistenceResult<AppletDeviceQueuePage> {
    let endpoint = input.endpoint;
    let authority = &endpoint.authority;
    if input.limit == 0
        || input.limit > 100
        || !matches!(
            endpoint.effective_scope,
            ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
        )
    {
        return Err(denied("native queue request has no supported exact scope"));
    }
    let mut held = crate::account_content_delivery::DeliveryGuard::begin(pool).await?;
    let mut realms = vec![
        authority.pcr_realm_id.clone(),
        endpoint.effective_scope.realm_id().clone(),
    ];
    realms.sort();
    realms.dedup();
    for realm in realms {
        let row=sql_query("SELECT to_jsonb(service_id) AS payload FROM realm_authorities WHERE realm_id=$1 FOR SHARE NOWAIT")
            .bind::<Text,_>(realm.as_str()).get_result::<JsonPayloadRow>(held.connection()).await.map_err(PersistenceError::database)?;
        if row.payload.as_str() != Some(authority.account_id.station_id.as_str()) {
            return Err(denied("native queue has no local current barrier"));
        }
    }
    let mut deadline = input.transport_expires_at.min(authority.expires_at);
    require_device(
        held.connection(),
        authority,
        &endpoint.effective_scope,
        deadline,
    )
    .await?;
    let (after, inputs) = if let Some(token) = input.after {
        let (position, record) = continuation(held.connection(), endpoint, token).await?;
        deadline = deadline.min(
            chrono::DateTime::from_timestamp_millis(record.expires_at_ms)
                .ok_or_else(|| denied("cursor expiry is invalid"))?,
        );
        (position, vec![record])
    } else {
        (0, vec![])
    };
    let proof = crate::boxed_future(|| {
        crate::applet_content_delivery::mls_scope_read_proof(
            held.connection(),
            endpoint,
            deadline,
            None,
        )
    })
    .await?;
    let binding = super::queue_authority::current_binding(
        held.connection(),
        authority.account_id.principal_id.as_str(),
        authority.device_id.as_str(),
    )
    .await?
    .ok_or_else(|| denied("native queue original endpoint binding is absent"))?;
    let scope =
        serde_json::to_value(&endpoint.effective_scope).map_err(PersistenceError::database)?;
    let rows=sql_query("SELECT position,delivery_json FROM mls_welcome_deliveries WHERE recipient=$1 AND recipient_endpoint_kind='device' AND recipient_device_id=$2 AND recipient_device_authorization=$3 AND recipient_authorization_event_ref=$4 AND delivery_json->'effective_scope'=$5 AND state='queued' AND position>$6 ORDER BY position LIMIT $7 FOR SHARE")
        .bind::<Text,_>(authority.account_id.principal_id.as_str()).bind::<Text,_>(authority.device_id.as_str()).bind::<Jsonb,_>(&binding)
        .bind::<Text,_>(authority.selector.authorization_ref.event_id.as_str()).bind::<Jsonb,_>(&scope).bind::<BigInt,_>(after).bind::<BigInt,_>((input.limit+1) as i64)
        .load::<QueueRow>(held.connection()).await.map_err(PersistenceError::database)?;
    let has_more = rows.len() > input.limit;
    let mut deliveries = Vec::new();
    let mut positions = Vec::new();
    for row in rows.into_iter().take(input.limit) {
        let welcome: arkret_wire::MlsWelcomeDelivery =
            serde_json::from_value(row.delivery_json).map_err(PersistenceError::database)?;
        deadline = deadline.min(
            crate::boxed_future(|| material_deadline(held.connection(), endpoint, &welcome))
                .await?,
        );
        positions.push(row.position);
        deliveries.push(RecipientDelivery::MlsWelcome {
            mls_welcome: welcome,
        });
    }
    let (ack_token, next_cursor) = if positions.is_empty() {
        (None, None)
    } else {
        let token = fresh_device_message_ack_token();
        let position = *positions.last().expect("non-empty queue page");
        // A continuation carries only positions already disclosed by this
        // exact endpoint/scope. Cumulative ACK must not cover unread objects
        // from other scopes interleaved in the durable recipient queue.
        let mut cumulative: Vec<i64> = if let Some(previous) = inputs.as_slice().first() {
            let prior: Vec<i64> = serde_json::from_value(
                previous
                    .target
                    .as_ref()
                    .and_then(|value| value.get("delivered_positions"))
                    .cloned()
                    .ok_or_else(|| {
                        cursor_error(
                            "cursor_integrity_invalid",
                            "native cursor has no delivered positions",
                        )
                    })?,
            )
            .map_err(|_| {
                cursor_error(
                    "cursor_integrity_invalid",
                    "native cursor delivered positions are invalid",
                )
            })?;
            if prior.is_empty()
                || prior[0] <= 0
                || !prior.windows(2).all(|pair| pair[0] < pair[1])
                || *prior.last().unwrap() > after
            {
                return Err(cursor_error(
                    "cursor_integrity_invalid",
                    "native cursor delivered positions exceed its cut",
                ));
            }
            // Retain only outstanding prior deliveries, so a long-running
            // poller does not accumulate its acknowledged queue history.
            #[derive(QueryableByName)]
            struct Position {
                #[diesel(sql_type=BigInt)]
                position: i64,
            }
            sql_query("SELECT position FROM mls_welcome_deliveries WHERE recipient=$1 AND recipient_endpoint_kind='device' AND recipient_device_id=$2 AND recipient_device_authorization=$3 AND delivery_json->'effective_scope'=$4 AND position=ANY($5) AND state='queued' ORDER BY position FOR SHARE NOWAIT")
                .bind::<Text,_>(authority.account_id.principal_id.as_str()).bind::<Text,_>(authority.device_id.as_str()).bind::<Jsonb,_>(&binding).bind::<Jsonb,_>(&scope).bind::<Array<BigInt>,_>(&prior)
                .load::<Position>(held.connection()).await.map_err(PersistenceError::database)?.into_iter().map(|row|row.position).collect()
        } else {
            Vec::new()
        };
        cumulative.extend_from_slice(&positions);
        sql_query("INSERT INTO device_message_ack_tokens(ack_token,recipient,device_id,recipient_device_authorization,effective_scope,delivered_positions,queue_position,issued_at,expires_at,consumed_at) VALUES($1,$2,$3,$4,$5,$6,$7,NOW(),$8,NULL)")
            .bind::<Text,_>(&token).bind::<Text,_>(authority.account_id.principal_id.as_str()).bind::<Text,_>(authority.device_id.as_str()).bind::<Jsonb,_>(&binding)
            .bind::<Jsonb,_>(&scope).bind::<Array<BigInt>,_>(&cumulative).bind::<BigInt,_>(position).bind::<Timestamptz,_>(Utc::now()+chrono::Duration::hours(24))
            .execute(held.connection()).await.map_err(PersistenceError::database)?;
        let cursor = arkret::hlc::Cursor::new_at(Utc::now(), 3_600_000)
            .map_err(PersistenceError::database)?;
        let record = SyncCursorRecord {
            handle: cursor.h.clone(),
            binding_subject: Some(subject(authority)?),
            device_id: Some(authority.device_id.to_string()),
            session_id: None,
            service_id: authority.account_id.station_id.clone(),
            filter_digest: None,
            purpose: arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1.to_owned(),
            positions: None,
            target: Some(
                json!({"queue_position":position,"endpoint":endpoint_binding(endpoint)?,"delivered_positions":cumulative}),
            ),
            issued_at_ms: cursor.issued_at.timestamp_millis(),
            expires_at_ms: cursor.expires_at.timestamp_millis(),
        };
        crate::sync_cursor::upsert_in_connection(held.connection(), &record, &inputs)
            .await
            .map_err(PgTransactionError::into_persistence)?;
        (
            Some(token),
            Some(cursor.encode().map_err(PersistenceError::database)?),
        )
    };
    crate::sync_cursor::validate_issuance_inputs(held.connection(), &inputs)
        .await
        .map_err(PgTransactionError::into_persistence)?;
    if Utc::now() >= deadline || !proof.permits_at(Utc::now()) {
        return Err(denied("native queue authority ended before publication"));
    }
    Ok(AppletDeviceQueuePage {
        outcome: DeviceMessagesGetOutcome {
            deliveries,
            ack_token,
            next_cursor,
            has_more,
            limited: Some(has_more),
            lost: Some(false),
        },
        guard: Box::new(PendingPage {
            held,
            proof,
            deadline,
        }),
    })
}

pub(super) async fn ack(
    pool: &PgPool,
    input: AppletDeviceQueueAck<'_>,
) -> PersistenceResult<Option<usize>> {
    let authority = input.authority;
    let scope = input.effective_scope;
    let token = input.body.ack_token.as_str();
    if token.is_empty() || token.len() > 1024 {
        return Ok(None);
    }
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_,PgTransactionError,_>(async |conn|{
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn,&authority.pcr_realm_id).await?;
        require_device(conn,authority,scope,input.transport_expires_at).await?;
        let Some(binding)=super::queue_authority::current_binding(conn,authority.account_id.principal_id.as_str(),authority.device_id.as_str()).await? else{return Ok(None)};
        let stored=sql_query("SELECT recipient,device_id,recipient_device_authorization,effective_scope,delivered_positions,expires_at,consumed_at FROM device_message_ack_tokens WHERE ack_token=$1 AND effective_scope IS NOT NULL FOR UPDATE")
            .bind::<Text,_>(token).get_result::<AckRow>(&mut *conn).await.optional()?;
        let Some(stored)=stored else{return Ok(None)};
        let scope=serde_json::to_value(scope).map_err(PersistenceError::database)?;
        if stored.recipient!=authority.account_id.principal_id.as_str() || stored.device_id!=authority.device_id.as_str()
            || stored.recipient_device_authorization!=binding || stored.effective_scope!=scope || Utc::now()>=stored.expires_at
            || stored.delivered_positions.is_empty() || stored.delivered_positions[0]<=0 || !stored.delivered_positions.windows(2).all(|pair|pair[0]<pair[1]) {return Ok(None);}
        require_device(conn,authority,input.effective_scope,input.transport_expires_at).await?;
        if stored.consumed_at.is_some(){return Ok(Some(0));}
        let count=sql_query("UPDATE mls_welcome_deliveries SET state='delivered',delivered_at=NOW() WHERE recipient=$1 AND recipient_endpoint_kind='device' AND recipient_device_id=$2 AND recipient_device_authorization=$3 AND position=ANY($4) AND delivery_json->'effective_scope'=$5 AND state='queued'")
            .bind::<Text,_>(authority.account_id.principal_id.as_str()).bind::<Text,_>(authority.device_id.as_str()).bind::<Jsonb,_>(binding).bind::<Array<BigInt>,_>(&stored.delivered_positions).bind::<Jsonb,_>(scope)
            .execute(&mut *conn).await?;
        sql_query("UPDATE device_message_ack_tokens SET consumed_at=NOW() WHERE ack_token=$1 AND consumed_at IS NULL").bind::<Text,_>(token).execute(&mut *conn).await?;
        require_device(conn,authority,input.effective_scope,input.transport_expires_at).await?;
        if Utc::now()>=stored.expires_at {return Err(denied("native ACK token expired before completion").into());}
        Ok(Some(count))
    }).await.map_err(PgTransactionError::into_persistence)
}
