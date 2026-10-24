//! Frozen stream discovery backed by immutable durable cursor instances.
//! Only the root instance stores the enumeration; continuations reference it.
//! Every page intersects that frozen set with a fresh caller authorization cut.

use std::collections::BTreeMap;

use arkret_server::{CursorAuthority, CursorAuthorityError, CursorBindingContext};
use arkret_wire::{RealmId, RealmStreamPage, RealmStreamRow};
use coland_http::error::AppError;
use coland_services::sync::CursorState;
use coland_storage::AccountRealmStreamList;
use serde::{Deserialize, Serialize};

use super::*;

const TTL_MS: i64 = 60 * 60 * 1000;
const PAGE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Position {
    Root {
        streams: Vec<RealmStreamRow>,
        after: usize,
    },
    Page {
        snapshot_handle: String,
        after: usize,
    },
}

fn invalid_cursor() -> AppError {
    crate::app_error!(
        CursorIntegrityInvalid,
        "stream enumeration binding is invalid"
    )
}

fn cursor_error(error: CursorAuthorityError) -> AppError {
    match error {
        CursorAuthorityError::ParamInvalid(message) => AppError::param_invalid(message)
            .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR),
        CursorAuthorityError::Expired => crate::app_error!(CursorExpired, "cursor has expired"),
        CursorAuthorityError::IntegrityInvalid => invalid_cursor(),
    }
}

fn unavailable() -> AppError {
    crate::app_error!(
        TemporarilyUnavailable,
        "the frozen stream cut cannot be confirmed"
    )
}

fn internal(error: impl std::fmt::Display) -> AppError {
    tracing::warn!(reason = %error, "stream discovery failed internally");
    AppError::internal("stream discovery is unavailable")
}

async fn check_revocation(
    state: &AppState,
    token: &str,
    record: &CursorState,
) -> Result<(), AppError> {
    let cursor = CursorAuthority::decode_stream(token).map_err(cursor_error)?;
    if crate::routing::events::sync::cursor_authority_revoked(
        state,
        &cursor,
        record,
        chrono::Utc::now().timestamp_millis(),
    )
    .await
    .map_err(crate::routing::events::sync::cursor_revoke_error)?
    {
        return Err(crate::app_error!(
            CursorRevoked,
            "cursor authority has been revoked"
        ));
    }
    Ok(())
}

#[handler]
pub(super) async fn realm_streams(req: &mut Request, depot: &Depot, res: &mut Response) {
    let Some(state) = app_state(depot, res) else {
        return;
    };
    let Some((session, account)) = authenticated_reader(
        state,
        req,
        res,
        ServiceOperationId::SELF_REALM_READ_STREAMS_V1,
    )
    .await
    else {
        return;
    };
    match page(state, req, &session, &account).await {
        Ok(page) => {
            no_store(res);
            res.render(Json(page));
        }
        Err(error) => {
            if let Some(reason) = error.reason_code.as_deref() {
                crate::error::render_error_with_reason_code(
                    res,
                    error.http_status(),
                    error.wire_code(),
                    &error.message,
                    reason,
                    None,
                );
            } else {
                crate::routing::render_error(
                    res,
                    error.http_status(),
                    error.wire_code(),
                    &error.message,
                );
            }
        }
    }
}

async fn page(
    state: &AppState,
    req: &mut Request,
    session: &coland_services::identity::SessionIdentityState,
    account: &AccountId,
) -> Result<RealmStreamPage, AppError> {
    let realm = req
        .param::<String>("realm_id")
        .and_then(|id| RealmId::new(id).ok())
        .ok_or_else(|| crate::app_error!(SchemaViolation, "realm_id is not a Realm id"))?;
    let limit = match req.query::<String>("limit") {
        Some(raw) => raw
            .parse::<usize>()
            .ok()
            .filter(|limit| (1..=500).contains(limit) && limit.to_string() == raw)
            .ok_or_else(|| {
                crate::app_error!(SchemaViolation, "limit must be an integer in 1..=500")
            })?,
        None => 500,
    };
    let digest = arkret_server::cursor_filter_digest(&serde_json::json!({
        "operation": ServiceOperationId::SELF_REALM_READ_STREAMS_V1,
        "realm_id": realm, "limit": limit,
    }))
    .map_err(cursor_error)?;
    let context = CursorBindingContext::new(
        String::from_utf8(arkret_canonical::canonical_json_bytes(account).map_err(internal)?)
            .map_err(internal)?,
        session.human_device_id().cloned(),
        state.service_core_id(),
        digest,
    );
    let token = req.query::<String>("cursor");
    let mut input_record = None;
    let (frozen, after, snapshot_handle, expires) = if let Some(token) = &token {
        let decoded = CursorAuthority::decode_stream(token).map_err(cursor_error)?;
        let stored = state
            .sync()
            .cursor(&decoded.h)
            .await
            .map_err(internal)?
            .ok_or_else(invalid_cursor)?;
        let binding = coland_http::util::cursor_binding_record_from_state(stored.clone())
            .map_err(cursor_error)?;
        let position = CursorAuthority::resolve_stream(&decoded, &context, Some(&binding))
            .map_err(cursor_error)?;
        check_revocation(state, token, &stored).await?;
        let position: Position = serde_json::from_value(position).map_err(|_| invalid_cursor())?;
        let tuple = match position {
            Position::Root { streams, after } => (
                streams,
                after,
                Some(stored.handle.clone()),
                stored.expires_at_ms,
            ),
            Position::Page {
                snapshot_handle,
                after,
            } => {
                let root = state
                    .sync()
                    .cursor(&snapshot_handle)
                    .await
                    .map_err(internal)?
                    .ok_or_else(invalid_cursor)?;
                let root_binding =
                    coland_http::util::cursor_binding_record_from_state(root.clone())
                        .map_err(cursor_error)?;
                if root_binding.context != context
                    || root_binding.purpose != arkret_wire::cursor::CursorPurpose::Stream
                    || root.expires_at_ms != stored.expires_at_ms
                {
                    return Err(invalid_cursor());
                }
                let Position::Root { streams, .. } =
                    serde_json::from_value(root_binding.positions).map_err(|_| invalid_cursor())?
                else {
                    return Err(invalid_cursor());
                };
                (streams, after, Some(snapshot_handle), root.expires_at_ms)
            }
        };
        input_record = Some(stored);
        tuple
    } else {
        (
            Vec::new(),
            0,
            None,
            chrono::Utc::now().timestamp_millis() + TTL_MS,
        )
    };
    let live = match state
        .authority_commits()
        .list_realm_streams_for_account(&realm, account, &state.service_core_id())
        .await
        .map_err(|_| unavailable())?
    {
        AccountRealmStreamList::Listed(rows) => rows,
        AccountRealmStreamList::NotVisible => return Err(AppError::not_found("not found")),
        AccountRealmStreamList::Unproved(_) => return Err(unavailable()),
    };
    let frozen = if token.is_none() {
        live.clone()
    } else {
        frozen
    };
    let (mut page, after) = select_page(&realm, &frozen, &live, after, limit, PAGE_BYTES)?;
    let mut issued = None;
    if page.has_more {
        let positions = match snapshot_handle {
            Some(snapshot_handle) => Position::Page {
                snapshot_handle,
                after,
            },
            None => Position::Root {
                streams: frozen,
                after,
            },
        };
        let (token, record) = CursorAuthority::mint_stream_until(
            context,
            serde_json::to_value(positions).map_err(internal)?,
            expires,
        )
        .map_err(cursor_error)?;
        // A continuation never extends the frozen root's original lifetime.
        if record.expires_at_ms > expires {
            return Err(unavailable());
        }
        let stored = CursorState {
            handle: record.handle,
            binding_subject: Some(record.context.binding_subject),
            device_id: record.context.device_id,
            session_id: Some(session.token_hash.clone()),
            service_id: record.context.service_id,
            filter_digest: Some(record.context.filter_digest),
            purpose: "stream".to_owned(),
            positions: Some(record.positions),
            target: None,
            issued_at_ms: record.issued_at_ms,
            expires_at_ms: record.expires_at_ms,
        };
        check_revocation(state, &token, &stored).await?;
        state
            .sync()
            .upsert_cursor(&stored)
            .await
            .map_err(internal)?;
        page.next_cursor = Some(token.clone());
        issued = Some((token, stored));
    }
    if let (Some(token), Some(record)) = (&token, &input_record) {
        check_revocation(state, token, record).await?;
    }
    if let Some((token, record)) = &issued {
        check_revocation(state, token, record).await?;
    }
    if session.expires_at <= chrono::Utc::now() {
        return Err(crate::app_error!(Unauthenticated, "session has expired"));
    }
    page.validate().map_err(internal)?;
    Ok(page)
}

#[cfg(test)]
mod tests {
    use arkret_wire::{CommitStreamRef, ReadableFloor, ReadableFloorReason};

    use super::*;

    fn fixture() -> (RealmId, Vec<RealmStreamRow>) {
        let realm: RealmId = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru"
            .parse()
            .unwrap();
        let head: arkret_wire::RealmCommitId =
            "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4"
                .parse()
                .unwrap();
        let mut rows = (0u64..3)
            .map(|index| {
                let mut bytes = [0u8; 33];
                bytes[0] = 1;
                bytes[1..9].copy_from_slice(&index.to_be_bytes());
                RealmStreamRow {
                    stream_ref: CommitStreamRef::Circle {
                        realm_id: realm.clone(),
                        circle_id: arkret_wire::CircleId::from_event_id(
                            &arkret_wire::EventId::from_token_bytes(bytes).unwrap(),
                        ),
                    },
                    head_commit_ref: head.clone(),
                    next_position: 10,
                    readable_floor: Some(ReadableFloor {
                        oldest_position: 0,
                        floor_commit_id: head.clone(),
                        floor_reason: ReadableFloorReason::StreamStart,
                    }),
                }
            })
            .collect::<Vec<_>>();
        rows.sort_by_cached_key(|row| {
            arkret_canonical::canonical_json_bytes(&row.stream_ref).unwrap()
        });
        (realm, rows)
    }

    #[test]
    fn page_budget_stops_before_the_first_unreturned_row() {
        let (realm, rows) = fixture();
        let first_size = arkret_canonical::canonical_json_bytes(&rows[0])
            .unwrap()
            .len()
            + 1;
        let (page, after) = select_page(&realm, &rows, &rows, 0, 500, 1024 + first_size).unwrap();
        assert_eq!(page.streams, rows[..1]);
        assert!(page.has_more);
        assert_eq!(after, 1);
        let (page, after) = select_page(&realm, &rows, &rows, after, 500, PAGE_BYTES).unwrap();
        assert_eq!(page.streams, rows[1..]);
        assert!(!page.has_more);
        assert_eq!(after, rows.len());
    }

    #[test]
    fn authorization_narrows_frozen_heads_and_never_relaxes_floors() {
        let (realm, rows) = fixture();
        let mut live = rows.clone();
        live.remove(0);
        live[0].next_position = 12;
        live[0].readable_floor.as_mut().unwrap().oldest_position = 4;
        live[0].readable_floor.as_mut().unwrap().floor_reason = ReadableFloorReason::MembershipJoin;
        live[1].readable_floor.as_mut().unwrap().oldest_position = 10;
        let (page, after) = select_page(&realm, &rows, &live, 0, 500, PAGE_BYTES).unwrap();
        assert_eq!(page.streams.len(), 1);
        assert_eq!(page.streams[0].next_position, 10);
        assert_eq!(
            page.streams[0]
                .readable_floor
                .as_ref()
                .unwrap()
                .oldest_position,
            4
        );
        assert_eq!(after, rows.len());
        assert!(!page.has_more);
        live[0].next_position = 9;
        assert!(select_page(&realm, &rows, &live, 0, 500, PAGE_BYTES).is_err());
    }
}

/// Frozen heads cannot advance, and a stricter current floor cannot be relaxed.
fn select_page(
    realm: &RealmId,
    frozen: &[RealmStreamRow],
    live: &[RealmStreamRow],
    after: usize,
    limit: usize,
    byte_limit: usize,
) -> Result<(RealmStreamPage, usize), AppError> {
    if after > frozen.len() {
        return Err(invalid_cursor());
    }
    let visible = live
        .iter()
        .map(|row| (&row.stream_ref, row))
        .collect::<BTreeMap<_, _>>();
    let mut page = RealmStreamPage {
        realm_id: realm.clone(),
        streams: Vec::new(),
        next_cursor: None,
        has_more: false,
    };
    // Reserve the bounded opaque cursor and response envelope before adding rows.
    let mut bytes = 1024;
    let mut next = after;
    for (index, original) in frozen.iter().enumerate().skip(after) {
        let Some(current) = visible.get(&original.stream_ref) else {
            next = index + 1;
            continue;
        };
        if current.next_position < original.next_position
            || (current.next_position == original.next_position
                && current.head_commit_ref != original.head_commit_ref)
        {
            return Err(unavailable());
        }
        let mut row = original.clone();
        match (&original.readable_floor, &current.readable_floor) {
            (Some(old), Some(now)) => {
                if now.oldest_position >= original.next_position {
                    next = index + 1;
                    continue;
                }
                if now.oldest_position == old.oldest_position
                    && now.floor_commit_id != old.floor_commit_id
                {
                    return Err(unavailable());
                }
                if now.oldest_position > old.oldest_position {
                    row.readable_floor = Some(now.clone());
                }
            }
            (None, Some(now)) => {
                if now.oldest_position >= original.next_position {
                    next = index + 1;
                    continue;
                }
                row.readable_floor = Some(now.clone());
            }
            (None, None) => {}
            (Some(_), None) => return Err(unavailable()),
        }
        let size = arkret_canonical::canonical_json_bytes(&row)
            .map_err(internal)?
            .len()
            + 1;
        if page.streams.len() == limit || bytes + size > byte_limit {
            if page.streams.is_empty() {
                return Err(crate::app_error!(
                    PayloadTooLarge,
                    "one stream row exceeds the page budget"
                ));
            }
            page.has_more = true;
            break;
        }
        page.streams.push(row);
        bytes += size;
        next = index + 1;
    }
    Ok((page, next))
}
