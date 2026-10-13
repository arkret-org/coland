//! Stateful sync-cursor lifecycle: immutable token minting,
//! durable handle persistence, parse/validate, revocation, and the EventsSubscribe
//! dropped/resync frame helper. Shared with sibling routing modules through
//! `sync.rs` re-exports.

use arkret_identifiers::DidCoreId;

use super::*;

#[derive(Debug, Default)]
pub struct SyncCursor {
    /// Validated immutable read inputs, never serialized into a wire cursor.
    pub input_authorities: Vec<CursorState>,
    /// Visible timeline frontier per Realm.
    pub positions: BTreeMap<String, i64>,
    /// Account aggregate projection frontier per Realm. This is a
    /// server-internal cursor vector carried inside the opaque handle binding;
    /// it is intentionally separate from `positions.realms` so metadata-only
    /// deltas cannot mask later visible timeline events.
    pub account_positions: BTreeMap<String, i64>,
    pub to_device_position: i64,
    pub account_summary_position: i64,
    /// Retained Station-CAS change-log position used only to prove that an
    /// account continuation still has complete replay coverage.
    pub account_data_change_position: i64,
    pub global_baseline: Option<Value>,
    pub detail_positions: BTreeMap<String, coland_storage::AccountDetailProgress>,
    pub detail_turn: bool,
    pub detail_next_realm: Option<String>,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct EventsQueryCursor {
    pub event_id: String,
}

#[derive(Debug)]
pub enum SyncCursorError {
    Invalid(&'static str),
    Mismatch(&'static str),
    Integrity(&'static str),
    Unavailable(&'static str),
    Expired,
    /// The cursor authority was revoked via `ak.self.account.command.revoke_cursor.v1`.
    /// Surfaced as `cursor_revoked`; MUST be raised before any server-side
    /// state advancement (to-device ack, account-subscribe resume, wait-for
    /// barrier release, dropped/resync recovery).
    Revoked,
}

pub(crate) const ACCOUNT_STREAM_CURSOR_PURPOSE: &str =
    arkret_wire::CapabilityActionId::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1;
pub(crate) const COMMITTED_STREAM_CURSOR_PURPOSE: &str =
    arkret_wire::CapabilityActionId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1;

/// Independent stream coordinates stay behind the existing opaque handle;
/// no private stream-set shape is exposed in the cursor token.
pub(crate) async fn committed_stream_cursor(
    state: &AppState,
    session: &SessionIdentityState,
    filter_digest: &str,
    positions: Value,
) -> Result<String, SyncCursorError> {
    let (subject, device, endpoint) = recipient_queue_cursor_binding(state, session)?;
    let target = json!({"endpoint":endpoint});
    let cursor = arkret_hlc::Cursor::new_at(Utc::now(), 3_600_000)
        .map_err(|_| SyncCursorError::Integrity("invalid committed stream expiry"))?;
    let handle = cursor.h.clone();
    state
        .sync()
        .upsert_cursor(&CursorState {
            handle,
            binding_subject: Some(subject),
            device_id: device,
            session_id: Some(session.token_hash.clone()),
            service_id: state.service_core_id(),
            filter_digest: Some(filter_digest.to_owned()),
            purpose: COMMITTED_STREAM_CURSOR_PURPOSE.to_owned(),
            positions: Some(positions),
            target: Some(target),
            issued_at_ms: cursor.issued_at.timestamp_millis(),
            expires_at_ms: cursor.expires_at.timestamp_millis(),
        })
        .await
        .map_err(|_| SyncCursorError::Integrity("cannot persist committed stream cursor"))?;
    cursor
        .encode()
        .map_err(|_| SyncCursorError::Integrity("cannot encode committed stream cursor"))
}

pub(crate) async fn parse_committed_stream_cursor(
    state: &AppState,
    session: &SessionIdentityState,
    filter_digest: &str,
    token: &str,
) -> Result<Value, SyncCursorError> {
    let now_ms = Utc::now().timestamp_millis();
    let cursor = decode_sync_cursor_for(token, now_ms, &arkret_hlc::CursorPurpose::Stream)?;
    if cursor.purpose != arkret_hlc::CursorPurpose::Stream {
        return Err(SyncCursorError::Invalid(
            "committed stream outer purpose mismatch",
        ));
    }
    let stored = stored_sync_cursor_record_by_handle(state, &cursor.h).await?;
    let (subject, device, endpoint) = recipient_queue_cursor_binding(state, session)?;
    validate_sync_binding(
        &cursor,
        &stored,
        &subject,
        device,
        state.service_core_id(),
        COMMITTED_STREAM_CURSOR_PURPOSE,
        Some(filter_digest),
        Some(json!({"endpoint":endpoint})),
        now_ms,
    )?;
    if cursor_authority_revoked(state, &cursor, &stored, now_ms).await? {
        return Err(SyncCursorError::Revoked);
    }
    stored.positions.ok_or(SyncCursorError::Integrity(
        "committed stream positions absent",
    ))
}
fn validate_sync_binding(
    cursor: &arkret_hlc::Cursor,
    stored: &CursorState,
    subject: &str,
    device: Option<String>,
    service: DidCoreId,
    operation: &str,
    filter: Option<&str>,
    target_scope: Option<Value>,
    now_ms: i64,
) -> Result<(), SyncCursorError> {
    use arkret_server::{CursorAuthority, CursorBindingContext, CursorBindingRecord};
    let digest = |operation: &str, filter: Option<&str>, target: Option<Value>| {
        arkret_server::cursor_filter_digest(&json!({
            "operation": operation, "filter": filter, "target": target
        }))
        .map_err(|_| SyncCursorError::Integrity("invalid cursor scope"))
    };
    let purpose = if stored.purpose == BARRIER_CURSOR_PURPOSE {
        arkret_hlc::CursorPurpose::Barrier
    } else {
        arkret_hlc::CursorPurpose::Stream
    };
    let expected_purpose = if operation == BARRIER_CURSOR_PURPOSE {
        arkret_hlc::CursorPurpose::Barrier
    } else {
        arkret_hlc::CursorPurpose::Stream
    };
    let stored_scope = match operation {
        COMMITTED_STREAM_CURSOR_PURPOSE => stored.target.clone(),
        DEVICE_MESSAGES_CURSOR_PURPOSE => stored
            .target
            .as_ref()
            .and_then(|value| value.get("endpoint"))
            .cloned(),
        _ => None,
    };
    let record = CursorBindingRecord {
        handle: stored.handle.clone(),
        context: CursorBindingContext::new(
            stored
                .binding_subject
                .as_deref()
                .ok_or(SyncCursorError::Integrity("missing cursor subject"))?,
            stored.device_id.clone(),
            stored.service_id.clone(),
            digest(
                &stored.purpose,
                stored.filter_digest.as_deref(),
                stored_scope,
            )?,
        ),
        purpose,
        positions: Value::Null,
        issued_at_ms: stored.issued_at_ms,
        expires_at_ms: stored.expires_at_ms,
    };
    let expected = CursorBindingContext::new(
        subject,
        device,
        service,
        digest(operation, filter, target_scope)?,
    );
    CursorAuthority::validate_binding(cursor, &expected_purpose, &expected, Some(&record), now_ms)
        .map_err(|error| match error {
            arkret_server::CursorAuthorityError::Expired => SyncCursorError::Expired,
            arkret_server::CursorAuthorityError::ParamInvalid(_) => {
                SyncCursorError::Invalid("invalid canonical cursor or context purpose")
            }
            arkret_server::CursorAuthorityError::IntegrityInvalid => {
                SyncCursorError::Integrity("cursor issuance or request binding mismatch")
            }
        })
}

pub(crate) const DEVICE_MESSAGES_CURSOR_PURPOSE: &str =
    arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1;
#[cfg(test)]
pub(crate) const STREAM_CURSOR_PURPOSE: &str = "stream";
pub(crate) const BARRIER_CURSOR_PURPOSE: &str = "barrier";

fn cursor_account_device(
    state: &AppState,
    session: Option<&SessionIdentityState>,
) -> (Option<arkret_wire::AccountId>, String) {
    let account_id = session.map(|session| {
        arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(session.actor.clone())
                .expect("authenticated actor must be a DID core id"),
            state.service_core_id(),
        )
    });
    let device_id = session
        .map(|session| session.require_human_device_id().clone())
        .unwrap_or_else(|| "anonymous".to_owned());
    (account_id, device_id)
}

fn cursor_binding_subject(account_id: Option<&arkret_wire::AccountId>) -> String {
    account_id.map_or_else(
        || "anonymous".to_owned(),
        |account_id| {
            String::from_utf8(
                arkret_canonical::canonical_json_bytes(account_id)
                    .expect("AccountId canonicalization cannot fail"),
            )
            .expect("AccountId canonical JSON is UTF-8")
        },
    )
}

#[cfg(test)]
pub async fn sync_token_for_client_sync(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    filter: Option<&serde_json::Value>,
    realms_positions: BTreeMap<String, i64>,
    account_realms_positions: BTreeMap<String, i64>,
    to_device_position: i64,
) -> String {
    sync_token_for_account_positions(
        state,
        session,
        filter,
        realms_positions,
        account_realms_positions,
        to_device_position,
        0,
        0,
        None,
        BTreeMap::new(),
        false,
        None,
        &[],
    )
    .await
    .expect("test account cursor must persist")
}

pub(crate) async fn sync_token_for_account_positions(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    filter: Option<&Value>,
    realms_positions: BTreeMap<String, i64>,
    account_realms_positions: BTreeMap<String, i64>,
    to_device_position: i64,
    account_summary_position: i64,
    account_data_change_position: i64,
    global_baseline: Option<Value>,
    detail_positions: BTreeMap<String, coland_storage::AccountDetailProgress>,
    detail_turn: bool,
    detail_next_realm: Option<String>,
    input_authorities: &[CursorState],
) -> Result<String, SyncCursorError> {
    let issued_at = chrono::Utc::now();
    let (account_id, device_id) = cursor_account_device(state, session);
    let binding_subject = cursor_binding_subject(account_id.as_ref());
    let filter_digest = account_filter_digest(filter);
    let positions = json!({
        "realms": realms_positions,
        "account_realms": account_realms_positions,
        "to_device": to_device_position,
        "account_summary": account_summary_position,
        "account_data_change": account_data_change_position,
        "global_baseline": global_baseline,
        "detail_positions": detail_positions,
        "detail_turn": detail_turn,
        "detail_next_realm": detail_next_realm,
        "detail_filter": filter.cloned().unwrap_or_else(|| json!({}))
    });
    let global_deadline = match global_baseline.as_ref() {
        Some(progress) => {
            let completed = progress.get("completed").ok_or(SyncCursorError::Integrity(
                "account baseline completion absent",
            ))?;
            let completed: BTreeSet<String> = serde_json::from_value(completed.clone())
                .map_err(|_| SyncCursorError::Integrity("account baseline completion invalid"))?;
            let pending_allowed = session.is_some_and(|session| {
                super::global_channels::pending_intents_allowed(
                    session.agent_session().is_some(),
                    session.account_pk.is_some(),
                )
            });
            if super::global_channels::global_baseline_complete_channels(
                &completed,
                pending_allowed,
            ) {
                None
            } else {
                Some(
                    progress
                        .get("snapshot_expires_at_ms")
                        .and_then(Value::as_i64)
                        .ok_or(SyncCursorError::Integrity(
                            "account baseline expiry invalid",
                        ))?,
                )
            }
        }
        None => None,
    };
    let deadline = detail_positions
        .values()
        .map(|progress| progress.expires_at_ms)
        .chain(global_deadline)
        .min();
    let ttl = deadline.map_or(3_600_000, |deadline| {
        (deadline - issued_at.timestamp_millis()).min(3_600_000)
    });
    if ttl <= 0 {
        return Err(SyncCursorError::Expired);
    }
    let cursor = arkret_hlc::Cursor::new_at(issued_at, ttl)
        .map_err(|_| SyncCursorError::Integrity("invalid account cursor expiry"))?;
    let handle = cursor.h.clone();
    let issued_at_ms = cursor.issued_at.timestamp_millis();
    let expires_at_ms = cursor.expires_at.timestamp_millis();
    state
        .sync()
        .upsert_cursor_with_inputs(
            &CursorState {
                handle: handle.clone(),
                binding_subject: Some(binding_subject),
                device_id: Some(device_id),
                session_id: session.map(|session| session.token_hash.clone()),
                service_id: DidCoreId::new(state.service_id().clone())
                    .expect("AppState service_id must be a validated DID core id"),
                filter_digest: Some(filter_digest),
                purpose: ACCOUNT_STREAM_CURSOR_PURPOSE.to_owned(),
                positions: Some(positions),
                target: None,
                issued_at_ms,
                expires_at_ms,
            },
            input_authorities,
        )
        .await
        .map_err(cursor_issuance_error)?;
    cursor
        .encode()
        .map_err(|_| SyncCursorError::Integrity("cannot encode account cursor"))
}

#[cfg(test)]
pub(crate) async fn sync_token_for_events_query(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    filter_digest: &str,
    event_id: &str,
) -> String {
    let issued_at = chrono::Utc::now();
    let (account_id, device_id) = cursor_account_device(state, session);
    let binding_subject = cursor_binding_subject(account_id.as_ref());
    let target = json!({ "event_id": event_id });
    let cursor = arkret_hlc::Cursor::new_at(issued_at, 60 * 60 * 1000)
        .expect("one-hour stream cursor is valid");
    let handle = cursor.h.clone();
    let issued_at_ms = cursor.issued_at.timestamp_millis();
    let expires_at_ms = cursor.expires_at.timestamp_millis();
    upsert_sync_cursor_record(
        state,
        CursorState {
            handle: handle.clone(),
            binding_subject: Some(binding_subject),
            device_id: Some(device_id),
            session_id: session.map(|session| session.token_hash.clone()),
            service_id: DidCoreId::new(state.service_id().clone())
                .expect("AppState service_id must be a validated DID core id"),
            filter_digest: Some(filter_digest.to_owned()),
            purpose: STREAM_CURSOR_PURPOSE.to_owned(),
            positions: None,
            target: Some(target),
            issued_at_ms,
            expires_at_ms,
        },
    )
    .await;
    cursor.encode().expect("SDK cursor encoding cannot fail")
}

#[cfg(test)]
pub(crate) fn encode_sync_cursor_value(cursor: Value) -> String {
    let bytes = arkret_canonical::canonical_json_bytes(&cursor)
        .unwrap_or_else(|_| cursor.to_string().into_bytes());
    format!("ak:cursor:{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// How often the durable sync-cursor handle table is swept for expired rows.
/// Each retry instance survives until its own expiry. Retained row count
/// depends on issuance frequency; the indexed batch sweep bounds each pass.
const SYNC_CURSOR_TTL_SWEEP_INTERVAL: Duration = Duration::from_secs(900);

/// Spawn the periodic TTL sweep for the durable sync-cursor handle table.
///
/// Immutable unexpired retry instances survive newer progress. Only the
/// independent sweeper reclaims expired rows; refusal paths do not delete.
pub fn spawn_sync_cursor_ttl_sweeper(
    state: AppState,
) -> std::sync::Arc<tokio::task::JoinHandle<()>> {
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SYNC_CURSOR_TTL_SWEEP_INTERVAL);
        // Skip the immediate first tick so we don't fire mid-boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let now = chrono::Utc::now();
            let now_ms = now.timestamp_millis();
            match state.sync().prune_expired_cursors(now_ms).await {
                Ok(0) => {}
                Ok(pruned) => tracing::debug!(
                    worker = "sync_cursor_ttl_sweep",
                    pruned,
                    "expired sync cursor handles pruned"
                ),
                Err(error) => tracing::warn!(
                    worker = "sync_cursor_ttl_sweep",
                    %error,
                    "sync cursor TTL sweep failed"
                ),
            }
            // api-conventions.md §6 — the generic `Idempotency-Key` cache shares
            // this periodic sweep so its mapping table stays bounded by the
            // per-record TTL instead of growing with every keyed write.
            match state.jobs().prune_expired_idempotency(now).await {
                Ok(0) => {}
                Ok(pruned) => tracing::debug!(
                    worker = "sync_cursor_ttl_sweep",
                    pruned,
                    "expired idempotency keys pruned"
                ),
                Err(error) => tracing::warn!(
                    worker = "sync_cursor_ttl_sweep",
                    %error,
                    "idempotency key TTL sweep failed"
                ),
            }
        }
    });
    std::sync::Arc::new(task)
}

#[cfg(test)]
/// Persist the immutable row behind a test issuance.
///
/// A failed write is downgraded to a warning rather than failing the sync
/// response: the client still gets its data, and if the row never lands the
/// next `after=` presentation fails handle lookup and the client recovers
/// through the spec's full-resync path (client-sync.md §12.3).
async fn upsert_sync_cursor_record(state: &AppState, record: CursorState) {
    if let Err(error) = state.sync().upsert_cursor(&record).await {
        tracing::warn!(%error, handle = %record.handle, "sync cursor handle upsert failed");
    }
}

async fn stored_sync_cursor_record_by_handle(
    state: &AppState,
    handle: &str,
) -> Result<CursorState, SyncCursorError> {
    state
        .sync()
        .cursor(handle)
        .await
        .map_err(|error| {
            tracing::warn!(%error, handle, "sync cursor handle lookup failed");
            SyncCursorError::Unavailable("sync cursor handle lookup failed")
        })?
        .ok_or(SyncCursorError::Integrity("sync cursor handle is unknown"))
}

fn cursor_position_map(
    positions_value: &Value,
    key: &'static str,
    missing_error: Option<&'static str>,
) -> Result<BTreeMap<String, i64>, SyncCursorError> {
    let Some(map) = positions_value.get(key).and_then(Value::as_object) else {
        return match missing_error {
            Some(message) => Err(SyncCursorError::Integrity(message)),
            None => Ok(BTreeMap::new()),
        };
    };
    Ok(map
        .iter()
        .filter_map(|(realm_id, position)| {
            position
                .as_i64()
                .map(|position| (realm_id.clone(), position))
        })
        .collect())
}

#[cfg(test)]
pub async fn parse_and_validate_sync_cursor(
    token: &str,
    state: &AppState,
    session: Option<&SessionIdentityState>,
    filter: Option<&serde_json::Value>,
    now_ms: i64,
) -> Result<SyncCursor, SyncCursorError> {
    parse_account_cursor(token, state, session, filter, now_ms, false).await
}

pub(crate) async fn parse_account_cursor(
    token: &str,
    state: &AppState,
    session: Option<&SessionIdentityState>,
    filter: Option<&Value>,
    now_ms: i64,
    replace_filter: bool,
) -> Result<SyncCursor, SyncCursorError> {
    let cursor = decode_sync_cursor_for(token, now_ms, &arkret_hlc::CursorPurpose::Stream)?;
    if cursor.purpose != arkret_hlc::CursorPurpose::Stream {
        return Err(SyncCursorError::Invalid(
            "after must be a v1 account cursor",
        ));
    }
    let record = stored_sync_cursor_record_by_handle(state, &cursor.h).await?;
    let (account, device) = cursor_account_device(state, session);
    let expected_filter = account_filter_digest(filter);
    let binding_filter = if replace_filter {
        record
            .filter_digest
            .as_deref()
            .ok_or(SyncCursorError::Integrity("missing cursor filter"))?
    } else {
        &expected_filter
    };
    validate_sync_binding(
        &cursor,
        &record,
        &cursor_binding_subject(account.as_ref()),
        Some(device),
        state.service_core_id(),
        ACCOUNT_STREAM_CURSOR_PURPOSE,
        Some(binding_filter),
        None,
        now_ms,
    )?;
    if cursor_authority_revoked(state, &cursor, &record, now_ms).await? {
        return Err(SyncCursorError::Revoked);
    }
    let positions_value = record
        .positions
        .as_ref()
        .ok_or(SyncCursorError::Integrity("missing account positions"))?;
    validate_account_positions_shape(positions_value)?;
    let mut positions = cursor_position_map(
        positions_value,
        "realms",
        Some("cursor handle is missing positions.realms"),
    )?;
    let mut account_positions = cursor_position_map(
        positions_value,
        "account_realms",
        Some("cursor handle is missing positions.account_realms"),
    )?;
    let mut detail_positions: BTreeMap<String, coland_storage::AccountDetailProgress> =
        serde_json::from_value(positions_value["detail_positions"].clone())
            .map_err(|_| SyncCursorError::Integrity("invalid current detail positions"))?;
    let filter_changed = positions_value.get("detail_filter") != filter;
    if replace_filter {
        // Explicit replacement always restarts the bounded detail baseline.
        // This also supports refreshing an invalidated Realm without changing
        // the demand window. Timeline/account coordinates restart only when
        // the window itself changed.
        if filter_changed {
            positions.clear();
            account_positions.clear();
        }
        detail_positions.clear();
    }
    let to_device_position = positions_value
        .get("to_device")
        .and_then(|position| position.as_i64())
        .unwrap_or_default();
    Ok(SyncCursor {
        input_authorities: vec![record.clone()],
        positions,
        account_positions,
        to_device_position,
        account_summary_position: positions_value
            .get("account_summary")
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        account_data_change_position: positions_value
            .get("account_data_change")
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        global_baseline: positions_value
            .get("global_baseline")
            .filter(|value| !value.is_null())
            .cloned(),
        detail_positions,
        detail_turn: replace_filter || positions_value["detail_turn"].as_bool().unwrap_or(false),
        detail_next_realm: if replace_filter {
            None
        } else {
            positions_value["detail_next_realm"]
                .as_str()
                .map(str::to_owned)
        },
    })
}

fn validate_account_positions_shape(value: &Value) -> Result<(), SyncCursorError> {
    const KEYS: &[&str] = &[
        "realms",
        "account_realms",
        "to_device",
        "account_summary",
        "account_data_change",
        "global_baseline",
        "detail_filter",
        "detail_positions",
        "detail_turn",
        "detail_next_realm",
    ];
    let object = value
        .as_object()
        .ok_or(SyncCursorError::Integrity("invalid account positions"))?;
    if object.len() != KEYS.len() || object.keys().any(|key| !KEYS.contains(&key.as_str())) {
        return Err(SyncCursorError::Integrity(
            "unsupported account positions layout",
        ));
    }
    for key in ["to_device", "account_summary", "account_data_change"] {
        if object
            .get(key)
            .and_then(Value::as_i64)
            .is_none_or(|position| position < 0)
        {
            return Err(SyncCursorError::Integrity("invalid account position"));
        }
    }
    if !object["detail_filter"].is_object()
        || !object["detail_positions"]
            .as_object()
            .is_some_and(|positions| positions.len() <= 16)
        || !object["detail_turn"].is_boolean()
        || !(object["detail_next_realm"].is_null() || object["detail_next_realm"].is_string())
        || !(object["global_baseline"].is_null() || object["global_baseline"].is_object())
    {
        return Err(SyncCursorError::Integrity("invalid account progress"));
    }
    Ok(())
}

#[cfg(test)]
mod account_position_shape_tests {
    use super::*;

    #[test]
    fn retired_global_coordinates_are_rejected_not_defaulted() {
        let current = json!({"realms":{},"account_realms":{},"to_device":0,"account_summary":0,"account_data_change":0,"global_baseline":null,"detail_filter":{},"detail_positions":{},"detail_turn":false,"detail_next_realm":null});
        validate_account_positions_shape(&current).unwrap();
        for key in ["device_lists", "notifications", "account_data", "devices"] {
            let mut retired = current.clone();
            retired
                .as_object_mut()
                .unwrap()
                .insert(key.to_owned(), json!({}));
            assert!(validate_account_positions_shape(&retired).is_err(), "{key}");
        }
        let mut missing = current;
        missing.as_object_mut().unwrap().remove("account_summary");
        assert!(validate_account_positions_shape(&missing).is_err());
    }
}

#[cfg(test)]
pub(crate) async fn parse_and_validate_events_query_cursor(
    token: &str,
    state: &AppState,
    session: Option<&SessionIdentityState>,
    filter_digest: &str,
    now_ms: i64,
) -> Result<EventsQueryCursor, SyncCursorError> {
    if !token.starts_with("ak:cursor:") {
        return Err(SyncCursorError::Invalid(
            "events query cursor must be a ak:cursor token",
        ));
    }
    let cursor = decode_sync_cursor_for(token, now_ms, &arkret_hlc::CursorPurpose::Stream)?;
    if cursor.purpose != arkret_hlc::CursorPurpose::Stream {
        return Err(SyncCursorError::Invalid(
            "cursor purpose does not match stream",
        ));
    }
    let record = stored_sync_cursor_record_by_handle(state, &cursor.h).await?;
    let (account, device) = cursor_account_device(state, session);
    validate_sync_binding(
        &cursor,
        &record,
        &cursor_binding_subject(account.as_ref()),
        Some(device),
        state.service_core_id(),
        STREAM_CURSOR_PURPOSE,
        Some(filter_digest),
        None,
        now_ms,
    )?;
    if cursor_authority_revoked(state, &cursor, &record, now_ms).await? {
        return Err(SyncCursorError::Revoked);
    }
    let target = record
        .target
        .as_ref()
        .and_then(|target| target.get("event_id"))
        .and_then(Value::as_str)
        .ok_or(SyncCursorError::Integrity(
            "events query cursor handle is missing target.event_id",
        ))?;
    if arkret_identifiers::EventId::new(target).is_err() {
        return Err(SyncCursorError::Integrity(
            "events query cursor target must be an event id",
        ));
    }
    Ok(EventsQueryCursor {
        event_id: target.to_owned(),
    })
}

pub(crate) async fn parse_and_validate_barrier_cursor(
    token: &str,
    state: &AppState,
    session: &SessionIdentityState,
    now_ms: i64,
) -> Result<String, SyncCursorError> {
    let cursor = decode_sync_cursor_for(token, now_ms, &arkret_hlc::CursorPurpose::Barrier)?;
    if cursor.purpose != arkret_hlc::CursorPurpose::Barrier {
        return Err(SyncCursorError::Invalid(
            "X-Arkret-Wait-For requires a barrier cursor",
        ));
    }
    let record = stored_sync_cursor_record_by_handle(state, &cursor.h).await?;
    let (account, device) = cursor_account_device(state, Some(session));
    validate_sync_binding(
        &cursor,
        &record,
        &cursor_binding_subject(account.as_ref()),
        Some(device),
        state.service_core_id(),
        BARRIER_CURSOR_PURPOSE,
        None,
        None,
        now_ms,
    )?;
    if cursor_authority_revoked(state, &cursor, &record, now_ms).await? {
        return Err(SyncCursorError::Revoked);
    }
    let event_id = record
        .target
        .as_ref()
        .and_then(|target| target.get("event_id"))
        .and_then(Value::as_str)
        .ok_or(SyncCursorError::Integrity(
            "barrier cursor handle is missing target.event_id",
        ))?;
    if arkret_identifiers::EventId::new(event_id).is_err() {
        return Err(SyncCursorError::Integrity(
            "barrier cursor target must be an event id",
        ));
    }
    let event_id_typed = arkret_wire::EventId::new(event_id.to_owned())
        .map_err(|_| SyncCursorError::Integrity("invalid barrier target"))?;
    let accepted = state
        .event_queries()
        .canonical_event(event_id)
        .await
        .map_err(|_| SyncCursorError::Unavailable("barrier history unavailable"))?
        .ok_or(SyncCursorError::Integrity(
            "barrier history cannot be proved",
        ))?;
    if !crate::routing::events::event_log::event_visible_to_session(state, &accepted, session).await
    {
        return Err(SyncCursorError::Integrity("barrier target is not readable"));
    }
    if record
        .target
        .as_ref()
        .and_then(|target| target.get("event_digest"))
        .and_then(Value::as_str)
        .is_some_and(|digest| digest != accepted.canonical_digest)
    {
        return Err(SyncCursorError::Integrity("barrier target digest mismatch"));
    }
    let committed = state
        .authority_commits()
        .committed_event(&event_id_typed)
        .await
        .map_err(|_| SyncCursorError::Unavailable("barrier commit unavailable"))?
        .ok_or(SyncCursorError::Integrity(
            "barrier exact Commit cannot be proved",
        ))?;
    if committed.event.event_id != event_id_typed || committed.commit.event_ref != event_id_typed {
        return Err(SyncCursorError::Integrity(
            "barrier Commit identity mismatch",
        ));
    }
    Ok(event_id.to_owned())
}

fn decode_sync_cursor(token: &str, now_ms: i64) -> Result<arkret_hlc::Cursor, SyncCursorError> {
    arkret_hlc::Cursor::decode_at(token, now_ms).map_err(|error| {
        if error.error_code() == Some(arkret_wire::ErrorCode::CursorExpired) {
            SyncCursorError::Expired
        } else {
            SyncCursorError::Invalid("cursor must use the canonical SDK wire profile")
        }
    })
}

fn decode_sync_cursor_for(
    token: &str,
    now_ms: i64,
    purpose: &arkret_hlc::CursorPurpose,
) -> Result<arkret_hlc::Cursor, SyncCursorError> {
    arkret_hlc::Cursor::decode_for_purpose_at(token, now_ms, purpose).map_err(|error| {
        if error.error_code() == Some(arkret_wire::ErrorCode::CursorExpired) {
            SyncCursorError::Expired
        } else {
            SyncCursorError::Invalid("invalid canonical cursor or context purpose")
        }
    })
}

#[cfg(test)]
pub fn decode_sync_cursor_value(token: &str) -> Result<serde_json::Value, SyncCursorError> {
    let cursor = arkret_hlc::Cursor::decode(token)
        .map_err(|_| SyncCursorError::Invalid("cursor must use the canonical SDK wire profile"))?;
    serde_json::to_value(cursor)
        .map_err(|_| SyncCursorError::Invalid("cursor cannot be represented as JSON"))
}

const FILTER_DIGEST_COLLECTION_KEYS: &[&str] =
    &["realms", "actors", "event_kinds", "not_event_kinds", "kind"];
const FILTER_DIGEST_FALSE_DEFAULT_KEYS: &[&str] =
    &["lazy_load_members", "include_redundant_members"];

pub(crate) fn normalized_filter_digest_value(filter: Option<&serde_json::Value>) -> Value {
    filter
        .map(normalize_filter_digest_collections)
        .unwrap_or_else(|| json!({}))
}

fn normalize_filter_digest_collections(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut normalized = serde_json::Map::new();
            for (key, value) in object {
                if FILTER_DIGEST_FALSE_DEFAULT_KEYS.contains(&key.as_str())
                    && value == &Value::Bool(false)
                {
                    continue;
                }
                let value = if FILTER_DIGEST_COLLECTION_KEYS.contains(&key.as_str()) {
                    normalize_filter_digest_string_collection(value)
                } else {
                    normalize_filter_digest_collections(value)
                };
                if FILTER_DIGEST_COLLECTION_KEYS.contains(&key.as_str())
                    && matches!(&value, Value::Array(values) if values.is_empty())
                {
                    continue;
                }
                normalized.insert(key.clone(), value);
            }
            Value::Object(normalized)
        }
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(normalize_filter_digest_collections)
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn normalize_filter_digest_string_collection(value: &Value) -> Value {
    let Value::Array(values) = value else {
        return normalize_filter_digest_collections(value);
    };
    let Some(strings) = values
        .iter()
        .map(Value::as_str)
        .collect::<Option<BTreeSet<_>>>()
    else {
        return Value::Array(
            values
                .iter()
                .map(normalize_filter_digest_collections)
                .collect(),
        );
    };
    Value::Array(
        strings
            .into_iter()
            .map(|value| Value::String(value.to_owned()))
            .collect(),
    )
}

pub(crate) fn account_filter_digest(filter: Option<&Value>) -> String {
    arkret_canonical::canonical_sha256(&filter.cloned().unwrap_or_else(|| json!({})))
        .expect("normalized account filter is canonical JSON")
}

pub fn sync_filter_digest(filter: Option<&serde_json::Value>) -> String {
    let filter = normalized_filter_digest_value(filter);
    let binding = json!({
        "filter": filter,
    });
    arkret_canonical::canonical_sha256(&binding)
        .unwrap_or_else(|_| arkret_canonical::sha256_digest(binding.to_string().as_bytes()))
}

/// `POST /_arkret/self/account/cursor/revoke` — `ak.self.account.command.revoke_cursor.v1`.
///
/// High-assurance optional endpoint: record a previously issued cursor
/// authority in the revocation set until its maximum TTL would have elapsed.
/// A revoked cursor thereafter returns `cursor_revoked` from
/// [`parse_and_validate_sync_cursor`] and never advances to-device ack,
/// account-subscribe resume position, wait-for barrier state, or dropped
/// recovery state. `revoke_scope` controls breadth (`this_cursor` default,
/// `same_device`, `same_session`).
#[salvo::oapi::endpoint(
    operation_id = "ak.self.account.command.revoke_cursor",
    summary = "Revoke an account read cursor",
    tags("account")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.account.command.revoke_cursor.v1"))]
pub(super) async fn account_cursor_revoke(
    aa: crate::routing::system::extract::AuthArgs,
    body: salvo::oapi::extract::JsonBody<
        arkret_models_identity::account::AccountCursorRevokeRequestBody,
    >,
    depot: &mut Depot,
    req: &mut Request,
) -> coland_http::result::JsonResult<arkret_models_identity::account::AccountCursorRevokeOutcome> {
    use coland_http::error::AppError;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    if session.human_device_id().is_none() {
        return Err(crate::app_error!(
            CapabilityDenied,
            "cursor revocation requires an account device"
        ));
    }
    let body = body.into_inner();

    let cursor = decode_sync_cursor(&body.cursor, chrono::Utc::now().timestamp_millis())
        .map_err(cursor_revoke_error)?;
    let record = stored_sync_cursor_record_by_handle(state, &cursor.h)
        .await
        .map_err(cursor_revoke_error)?;
    let (account, device) = cursor_account_device(state, Some(&session));
    // The caller cannot choose an operation/filter for revocation; the exact
    // persisted instance supplies these, while ownership is always checked.
    let scope_target = match record.purpose.as_str() {
        COMMITTED_STREAM_CURSOR_PURPOSE => record.target.clone(),
        DEVICE_MESSAGES_CURSOR_PURPOSE => record
            .target
            .as_ref()
            .and_then(|v| v.get("endpoint"))
            .cloned(),
        _ => None,
    };
    validate_sync_binding(
        &cursor,
        &record,
        &cursor_binding_subject(account.as_ref()),
        Some(device),
        state.service_core_id(),
        &record.purpose,
        record.filter_digest.as_deref(),
        scope_target,
        chrono::Utc::now().timestamp_millis(),
    )
    .map_err(cursor_revoke_error)?;
    if body.revoke_scope == arkret_models_identity::account::CursorRevokeScope::SameSession
        && record.session_id.as_deref() != Some(session.token_hash.as_str())
    {
        return Err(crate::app_error!(
            CursorIntegrityInvalid,
            "cursor session ownership mismatch"
        ));
    }
    let reason_code = body.reason_code.as_str().trim();
    if reason_code.is_empty() {
        return Err(AppError::param_invalid("reason_code is required"));
    }
    let scope = body.revoke_scope;
    let scope_value = match scope {
        arkret_models_identity::account::CursorRevokeScope::ThisCursor => "this_cursor",
        arkret_models_identity::account::CursorRevokeScope::SameDevice => "same_device",
        arkret_models_identity::account::CursorRevokeScope::SameSession => "same_session",
    };

    let revoked_at = arkret_canonical::normalize_timestamp_canonical(now());
    let expires_at = if scope == arkret_models_identity::account::CursorRevokeScope::ThisCursor {
        cursor.expires_at
    } else {
        revoked_at + chrono::Duration::seconds(CURSOR_MAX_TTL_SECONDS)
    };
    let device_id = if matches!(
        scope,
        arkret_models_identity::account::CursorRevokeScope::ThisCursor
    ) {
        None
    } else {
        Some(session.require_human_device_id().clone())
    };
    let application_record = coland_services::sync::CursorRevocationState {
        cursor_digest: sha256_hex(cursor.h.as_bytes()),
        account_id: arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(session.actor.clone()).map_err(|error| {
                AppError::internal(format!(
                    "authenticated account principal is invalid: {error}"
                ))
            })?,
            state.service_core_id(),
        ),
        device_id,
        session_id: record.session_id.clone(),
        scope: scope_value.to_owned(),
        reason_code: reason_code.to_owned(),
        revoked_at,
        expires_at,
    };
    // Every consumer queries the durable ledger before advancing.
    state
        .sync()
        .record_cursor_revocation(&application_record)
        .await
        .map_err(|error| {
            AppError::internal(format!("failed to persist cursor revocation: {error}"))
        })?;
    let entries = state
        .sync()
        .active_cursor_revocations(revoked_at)
        .await
        .map_err(|error| AppError::internal(format!("cannot reload cursor revocation: {error}")))?;
    let effective_expiry = entries
        .iter()
        .find(|entry| {
            entry.cursor_digest == application_record.cursor_digest
                && entry.account_id == application_record.account_id
                && entry.scope == application_record.scope
        })
        .ok_or_else(|| AppError::internal("cursor revocation missing after persistence"))?
        .expires_at;

    crate::json_ok(
        arkret_models_identity::account::AccountCursorRevokeOutcome {
            revoked: true,
            expires_at: effective_expiry,
            revoke_scope_effective: Some(scope),
        },
    )
}

pub(super) async fn account_input_authorities(
    state: &AppState,
    body: &SyncRequestBody,
    wait_for: Option<&str>,
) -> Result<Vec<CursorState>, SyncCursorError> {
    let mut tokens = Vec::new();
    tokens.extend(body.after.as_deref());
    tokens.extend(
        body.realm_list
            .as_ref()
            .and_then(|page| page.after.as_ref())
            .map(|token| token.as_str()),
    );
    tokens.extend(wait_for);
    let mut records = Vec::new();
    for token in tokens {
        let cursor = decode_sync_cursor(token, Utc::now().timestamp_millis())?;
        let record = stored_sync_cursor_record_by_handle(state, &cursor.h).await?;
        if !records
            .iter()
            .any(|entry: &CursorState| entry.handle == record.handle)
        {
            records.push(record);
        }
    }
    Ok(records)
}

fn cursor_issuance_error(error: coland_services::ServiceError) -> SyncCursorError {
    tracing::warn!(%error, "cursor persistence failed");
    match &error {
        coland_services::ServiceError::Conflict(detail)
            if detail.starts_with("cursor_revoked:") =>
        {
            SyncCursorError::Revoked
        }
        coland_services::ServiceError::Conflict(detail)
            if detail.starts_with("cursor_expired:") =>
        {
            SyncCursorError::Expired
        }
        coland_services::ServiceError::Conflict(detail)
            if detail.starts_with("cursor_integrity_invalid:") =>
        {
            SyncCursorError::Integrity("input authority changed during issuance")
        }
        _ => SyncCursorError::Unavailable("cannot persist cursor"),
    }
}

pub(super) fn issuance_problem(error: SyncCursorError) -> Box<arkret_wire::Problem> {
    let error = cursor_revoke_error(error);
    Box::new(arkret_wire::Problem::from_code(
        error.wire_code(),
        "Account read input authority changed during issuance",
    ))
}

pub(crate) fn cursor_revoke_error(error: SyncCursorError) -> coland_http::error::AppError {
    match error {
        SyncCursorError::Expired => crate::app_error!(CursorExpired, "cursor has expired"),
        SyncCursorError::Unavailable(message) => crate::app_error!(TemporarilyUnavailable, message),
        SyncCursorError::Revoked => {
            crate::app_error!(CursorRevoked, "cursor authority has been revoked")
        }
        SyncCursorError::Invalid(message) => coland_http::error::AppError::param_invalid(message)
            .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR),
        _ => crate::app_error!(
            CursorIntegrityInvalid,
            "invalid cursor issuance or ownership"
        ),
    }
}

/// Returns `true` when `token` (or the authenticated session it is bound to)
/// has an active revocation recorded by [`account_cursor_revoke`]. Reads the
/// durable ledger without mutating cursor or revocation retention.
pub(crate) async fn cursor_authority_revoked(
    state: &AppState,
    cursor: &arkret_hlc::Cursor,
    record: &CursorState,
    now_ms: i64,
) -> Result<bool, SyncCursorError> {
    let now = chrono::DateTime::from_timestamp_millis(now_ms)
        .ok_or(SyncCursorError::Integrity("invalid cursor clock"))?;
    let entries = state
        .sync()
        .active_cursor_revocations(now)
        .await
        .map_err(|_| SyncCursorError::Unavailable("cursor revocation ledger unavailable"))?;
    let account: Option<arkret_wire::AccountId> = record
        .binding_subject
        .as_deref()
        .and_then(|subject| serde_json::from_str(subject).ok());
    let revoked = coland_services::sync::SyncService::revoked_in(
        &entries,
        &sha256_hex(cursor.h.as_bytes()),
        account.as_ref(),
        record.device_id.as_deref(),
        record.session_id.as_deref(),
        now,
    );
    Ok(revoked)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct RealmListPosition {
    pub watermark: i64,
    pub global_watermark: i64,
    pub expires_at_ms: i64,
    pub after: Option<coland_storage::AccountSummaryKey>,
    pub snapshot_cursor: Option<arkret_wire::Cursor>,
}

pub(crate) async fn realm_list_token(
    state: &AppState,
    session: &SessionIdentityState,
    position: &RealmListPosition,
    input_authorities: &[CursorState],
) -> Result<arkret_wire::Cursor, SyncCursorError> {
    let (account, device) = cursor_account_device(state, Some(session));
    let subject = cursor_binding_subject(account.as_ref());
    let target = serde_json::to_value(position)
        .map_err(|_| SyncCursorError::Integrity("invalid list position"))?;
    let now = chrono::Utc::now();
    let ttl = position.expires_at_ms - now.timestamp_millis();
    if ttl <= 0 {
        return Err(SyncCursorError::Expired);
    }
    if let Some(snapshot_token) = position.snapshot_cursor.as_ref() {
        let snapshot = parse_realm_list_cursor(state, session, snapshot_token.as_str()).await?;
        if snapshot.after.is_some()
            || snapshot.watermark != position.watermark
            || snapshot.global_watermark != position.global_watermark
            || snapshot.expires_at_ms != position.expires_at_ms
        {
            return Err(SyncCursorError::Integrity("list snapshot binding mismatch"));
        }
        if position.after.is_none() {
            return Ok(snapshot_token.clone());
        }
    }
    let mut inputs = input_authorities.to_vec();
    if let Some(token) = position.snapshot_cursor.as_ref() {
        let cursor = decode_sync_cursor(token.as_str(), now.timestamp_millis())?;
        let record = stored_sync_cursor_record_by_handle(state, &cursor.h).await?;
        if !inputs.iter().any(|input| input.handle == record.handle) {
            inputs.push(record);
        }
    }
    let issued_at = chrono::DateTime::from_timestamp_millis(position.expires_at_ms - 3_600_000)
        .ok_or(SyncCursorError::Integrity("invalid list snapshot time"))?;
    let cursor = arkret_hlc::Cursor::new_at(issued_at, 3_600_000)
        .map_err(|_| SyncCursorError::Integrity("invalid list expiry"))?;
    let handle = cursor.h.clone();
    state
        .sync()
        .upsert_cursor_with_inputs(
            &CursorState {
                handle,
                binding_subject: Some(subject),
                device_id: Some(device),
                session_id: Some(session.token_hash.clone()),
                service_id: state.service_core_id(),
                filter_digest: None,
                purpose: "realm_list".to_owned(),
                positions: None,
                target: Some(target),
                issued_at_ms: cursor.issued_at.timestamp_millis(),
                expires_at_ms: cursor.expires_at.timestamp_millis(),
            },
            &inputs,
        )
        .await
        .map_err(cursor_issuance_error)?;
    arkret_wire::Cursor::new(
        cursor
            .encode()
            .map_err(|_| SyncCursorError::Integrity("cannot encode list cursor"))?,
    )
    .map_err(|_| SyncCursorError::Integrity("invalid encoded list cursor"))
}

pub(crate) async fn parse_realm_list_cursor(
    state: &AppState,
    session: &SessionIdentityState,
    token: &str,
) -> Result<RealmListPosition, SyncCursorError> {
    let now = chrono::Utc::now().timestamp_millis();
    let cursor = decode_sync_cursor_for(token, now, &arkret_hlc::CursorPurpose::Stream)?;
    let stored = stored_sync_cursor_record_by_handle(state, &cursor.h).await?;
    let (account, device) = cursor_account_device(state, Some(session));
    validate_sync_binding(
        &cursor,
        &stored,
        &cursor_binding_subject(account.as_ref()),
        Some(device),
        state.service_core_id(),
        "realm_list",
        None,
        None,
        now,
    )?;
    if cursor_authority_revoked(state, &cursor, &stored, now).await? {
        return Err(SyncCursorError::Revoked);
    }
    let mut position: RealmListPosition = serde_json::from_value(
        stored
            .target
            .ok_or(SyncCursorError::Integrity("missing list position"))?,
    )
    .map_err(|_| SyncCursorError::Integrity("invalid list position"))?;
    if position.after.is_none() && position.snapshot_cursor.is_none() {
        position.snapshot_cursor = Some(
            arkret_wire::Cursor::new(token.to_owned())
                .map_err(|_| SyncCursorError::Integrity("invalid snapshot cursor"))?,
        );
    }
    Ok(position)
}

/// Queue continuation has its own operation binding and never advances an account stream.
fn recipient_queue_cursor_binding(
    state: &AppState,
    session: &SessionIdentityState,
) -> Result<(String, Option<String>, Value), SyncCursorError> {
    let selector = crate::routing::identity::device_messages::recipient_queue_selector(session)
        .map_err(|_| SyncCursorError::Mismatch("recipient queue selector unavailable"))?;
    match selector {
        coland_services::delivery::RecipientQueueSelector::HumanDevice {
            recipient,
            device_id,
        } => {
            let (account, _) = cursor_account_device(state, Some(session));
            Ok((
                cursor_binding_subject(account.as_ref()),
                Some(device_id.clone()),
                json!({"kind":"human_device","recipient":recipient,"device_id":device_id}),
            ))
        }
        coland_services::delivery::RecipientQueueSelector::AgentRuntime {
            agent_id,
            verification_method,
            authorization_event_ref,
        } => Ok((
            agent_id.clone(),
            None,
            json!({"kind":"agent_runtime","agent_id":agent_id,
                "verification_method":verification_method,
                "authorization_event_ref":authorization_event_ref}),
        )),
    }
}

pub(crate) async fn device_messages_cursor(
    state: &AppState,
    session: &SessionIdentityState,
    position: i64,
) -> Result<String, SyncCursorError> {
    let (subject, device, endpoint) = recipient_queue_cursor_binding(state, session)?;
    let target = json!({"queue_position":position,"endpoint":endpoint});
    let cursor = arkret_hlc::Cursor::new_at(chrono::Utc::now(), 3_600_000)
        .map_err(|_| SyncCursorError::Integrity("invalid queue expiry"))?;
    let handle = cursor.h.clone();
    state
        .sync()
        .upsert_cursor(&CursorState {
            handle,
            binding_subject: Some(subject),
            device_id: device,
            session_id: Some(session.token_hash.clone()),
            service_id: state.service_core_id(),
            filter_digest: None,
            purpose: DEVICE_MESSAGES_CURSOR_PURPOSE.to_owned(),
            positions: None,
            target: Some(target),
            issued_at_ms: cursor.issued_at.timestamp_millis(),
            expires_at_ms: cursor.expires_at.timestamp_millis(),
        })
        .await
        .map_err(|_| SyncCursorError::Integrity("cannot persist queue cursor"))?;
    cursor
        .encode()
        .map_err(|_| SyncCursorError::Integrity("cannot encode queue cursor"))
}

pub(crate) async fn parse_device_messages_cursor(
    token: &str,
    state: &AppState,
    session: &SessionIdentityState,
    now_ms: i64,
) -> Result<i64, SyncCursorError> {
    let cursor = decode_sync_cursor_for(token, now_ms, &arkret_hlc::CursorPurpose::Stream)?;
    if cursor.purpose != arkret_hlc::CursorPurpose::Stream {
        return Err(SyncCursorError::Invalid(
            "queue cursor outer purpose mismatch",
        ));
    }
    let stored = stored_sync_cursor_record_by_handle(state, &cursor.h).await?;
    let (subject, device, endpoint) = recipient_queue_cursor_binding(state, session)?;
    validate_sync_binding(
        &cursor,
        &stored,
        &subject,
        device,
        state.service_core_id(),
        DEVICE_MESSAGES_CURSOR_PURPOSE,
        None,
        Some(endpoint),
        now_ms,
    )?;
    if stored.positions.is_some() {
        return Err(SyncCursorError::Integrity("unexpected queue positions"));
    }
    if cursor_authority_revoked(state, &cursor, &stored, now_ms).await? {
        return Err(SyncCursorError::Revoked);
    }
    stored
        .target
        .as_ref()
        .and_then(|target| target.get("queue_position"))
        .and_then(Value::as_i64)
        .filter(|position| *position >= 0)
        .ok_or(SyncCursorError::Integrity("queue position absent"))
}
