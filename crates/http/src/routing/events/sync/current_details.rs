//! Realm detail delivery: caller-proved stream windows at one frozen cut.
//!
//! A window is frozen by `freeze_account_realm_window` at a single durable cut
//! that proves the Account's complete disclosure, delivers the live delta
//! after the head this cursor already delivered (or, without one, the last
//! `window_limit` Commits of the Realm stream), and names a
//! `window_start_basis` only when an exact snapshot already issued to the
//! Account sits at the anchor and is reserved for the window's consumable
//! period; otherwise a limited window is `preview_only`. The window deadline,
//! the basis reservation and the Account cursor that carries the window's
//! progress share one `expires_at_ms`.
//!
//! Each selected visible stream has its own window and basis. The current
//! result retains every stream head disclosed at the same signed cut.

use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountFilter, AccountSubscribeFrame, AccountSubscribeFrameKind, AccountSubscribeRealms,
    RealmSyncEntry,
};
use arkret_models_collaboration::sync_frames::current_results::AccountCurrentView;
use arkret_models_collaboration::sync_frames::demand_sync::{
    ACCOUNT_SYNC_DEFAULT_WINDOW_LIMIT, ACCOUNT_SYNC_MAX_FRAME_BYTES, RealmDetailErrorCode,
    RealmDetailUnavailable,
};
use coland_storage::{AccountDetailProgress, AccountRealmWindowRequest};

use super::*;

/// Consumable period of a frozen window and of its basis reservation. It is
/// the longest a reservation may claim, which is also the Account cursor's
/// own maximum lifetime.
const WINDOW_TTL_MS: i64 = coland_storage::MAX_ACCOUNT_WINDOW_RESERVATION_MS;
/// A delivered window is refrozen once less than this remains, so the cursor
/// lineage that carries it is not forced to expire with the old window.
const WINDOW_RENEW_BEFORE_MS: i64 = WINDOW_TTL_MS / 2;
/// Frame bytes kept for the envelope, cursor, window scalars and any
/// `unavailable` siblings; the atomic window rows get the rest.
const DETAIL_ENVELOPE_RESERVATION: usize = 64 * 1024;

fn control(kind: &str) -> AccountSubscribeFrame {
    serde_json::from_value(json!({ "kind": kind })).expect("closed control frame")
}

/// The part of the stream selection this Station can serve for one Realm.
#[derive(Debug, PartialEq, Eq)]
enum RealmSelection {
    /// Default bounded visible set.
    Default,
    /// Exact caller-selected streams for this Realm.
    Explicit(Vec<arkret_wire::CommitStreamRef>),
    /// `stream_refs` selects none of this Realm's streams: nothing is owed.
    NotSelected,
}

fn realm_selection(filter: &AccountFilter, realm: &RealmId) -> RealmSelection {
    let Some(stream_refs) = &filter.stream_refs else {
        return RealmSelection::Default;
    };
    let selected = stream_refs
        .iter()
        .filter(|stream_ref| stream_ref.realm_id() == realm)
        .cloned()
        .collect::<Vec<_>>();
    if selected.is_empty() {
        RealmSelection::NotSelected
    } else {
        RealmSelection::Explicit(selected)
    }
}

/// Only bindings still selected by this request owe minimum-head coverage.
pub(super) async fn continuation_heads_covered(
    state: &AppState,
    account: &arkret_wire::AccountId,
    body: &SyncRequestBody,
    after: &SyncCursor,
) -> coland_services::ServiceResult<bool> {
    let Some(filter) = body.filter.as_ref() else {
        return Ok(true);
    };
    for realm in filter.realm_ids.iter().flatten() {
        let Some(progress) = after.detail_positions.get(realm.as_str()) else {
            continue;
        };
        let selection = realm_selection(filter, realm);
        let (heads, _) = selected_visible_heads(&progress.stream_heads, realm, &selection);
        if heads.is_empty() {
            continue;
        }
        if !state
            .authority_commits()
            .account_continuation_heads_covered(realm, account, &heads)
            .await?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether a delivered window must be replaced by a newly frozen one.
fn selected_visible_heads(
    visible: &[arkret_wire::CommitStreamHead],
    realm: &RealmId,
    selection: &RealmSelection,
) -> (Vec<arkret_wire::CommitStreamHead>, bool) {
    let mut heads = match selection {
        RealmSelection::Default => visible.to_vec(),
        RealmSelection::Explicit(refs) => refs
            .iter()
            .filter_map(|stream| {
                visible
                    .iter()
                    .find(|head| &head.stream_ref == stream)
                    .cloned()
            })
            .collect(),
        RealmSelection::NotSelected => Vec::new(),
    };
    heads.sort_by_key(|head| {
        arkret_canonical::canonical_json_bytes(&head.stream_ref).unwrap_or_default()
    });
    let limited = matches!(selection, RealmSelection::Default) && heads.len() > 64;
    if limited {
        let realm_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let realm_head = heads
            .iter()
            .find(|head| head.stream_ref == realm_ref)
            .cloned();
        heads.retain(|head| head.stream_ref != realm_ref);
        heads.truncate(63);
        if let Some(realm_head) = realm_head {
            heads.push(realm_head);
        }
        heads.sort_by_key(|head| {
            arkret_canonical::canonical_json_bytes(&head.stream_ref).unwrap_or_default()
        });
    }
    (heads, limited)
}

fn needs_new_window(
    progress: Option<&AccountDetailProgress>,
    generation: u64,
    selected_heads: &[arkret_wire::CommitStreamHead],
    streams_limited: bool,
    now_ms: i64,
) -> bool {
    progress.is_none_or(|progress| {
        progress.expires_at_ms - now_ms < WINDOW_RENEW_BEFORE_MS
            || progress.governance_generation != generation
            || progress.streams_limited != streams_limited
            || progress.stream_heads.len() != selected_heads.len()
            || selected_heads.iter().any(|selected| {
                progress
                    .stream_heads
                    .iter()
                    .find(|head| head.stream_ref == selected.stream_ref)
                    != Some(selected)
            })
    })
}

fn unavailable(error_code: RealmDetailErrorCode) -> RealmSyncEntry {
    RealmSyncEntry {
        unavailable: Some(RealmDetailUnavailable { error_code }),
        ..RealmSyncEntry::default()
    }
}

/// The window, its rows, and the typed current of the same proved cut. The
/// current is the Station's result at the window head: it never depends on
/// the window start, so a `preview_only` window still carries it and the
/// client decides what it may install.
fn window_entry(
    realm: &RealmId,
    window: coland_storage::AccountRealmWindow,
    cursor: &str,
    baseline_revision: Option<u64>,
) -> RealmSyncEntry {
    let mut windows = vec![window.window];
    windows.extend(window.additional_windows);
    windows.sort_by_key(|entry| {
        arkret_canonical::canonical_json_bytes(&entry.stream_ref).unwrap_or_default()
    });
    RealmSyncEntry {
        baseline: baseline_revision.map(|cut_revision| {
            arkret_models_collaboration::sync_frames::account_subscribe::RealmDetailBaseline {
                snapshot_cursor: format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()),
                cut_revision,
                coverage: arkret_models_collaboration::sync_frames::current_results::AccountCurrentCoverage {
                    realm_id: realm.clone(),
                    stream_heads: window.current_stream_heads.clone(),
                    complete_for_authorized_streams: true,
                },
                complete: true,
            }
        }),
        streams: Some(windows),
        streams_limited: window.streams_limited.then_some(true),
        window_snapshot_cursor: Some(cursor.to_owned()),
        current: Some(AccountCurrentView {
            realm_id: realm.clone(),
            governance_generation: window.governance_generation,
            stream_heads: window.current_stream_heads,
            entries: window.current_state_entries,
        }),
        committed_events: Some(window.committed_events),
        ..RealmSyncEntry::default()
    }
}

/// Order the requested Realms so the scan resumes after the Realm the
/// previous detail frame answered.
fn round_robin(mut realms: Vec<RealmId>, last: Option<&str>) -> Vec<RealmId> {
    realms.sort();
    realms.dedup();
    let start = realms
        .iter()
        .position(|realm| last.is_none_or(|last| realm.as_str() > last))
        .unwrap_or(0);
    realms.rotate_left(start);
    realms
}

enum Freeze {
    Window(Box<RealmSyncEntry>, AccountDetailProgress),
    Unavailable(RealmDetailErrorCode),
}

async fn freeze(
    state: &AppState,
    account: &arkret_wire::AccountId,
    realm: &RealmId,
    window_limit: u32,
    delivered_heads: Vec<arkret_wire::CommitStreamHead>,
    selected_stream_refs: Option<Vec<arkret_wire::CommitStreamRef>>,
) -> Result<Freeze, String> {
    // Reserve the Account-summary cut first (0441): the reservation keeps
    // it readable until the cursor that carries `retained_revision` is saved.
    let (retained_revision, _) = state
        .sync()
        .account_sync_watermarks()
        .await
        .map_err(|error| error.to_string())?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let window_cursor =
        arkret_wire::Cursor::new(format!("ak:cursor:{}", uuid::Uuid::now_v7().as_simple()))
            .map_err(|error| error.to_string())?;
    let expires_at_ms = now_ms + WINDOW_TTL_MS;
    let request = AccountRealmWindowRequest {
        realm_id: realm.clone(),
        account: account.clone(),
        issuer: state.service_core_id(),
        window_limit,
        window_cursor: window_cursor.as_str().to_owned(),
        expires_at_ms,
        now_ms,
        byte_budget: ACCOUNT_SYNC_MAX_FRAME_BYTES - DETAIL_ENVELOPE_RESERVATION,
        delivered_heads,
        selected_stream_refs,
    };
    let baseline_revision = if request.delivered_heads.is_empty() {
        Some(u64::try_from(retained_revision).map_err(|error| error.to_string())?)
    } else {
        None
    };
    let verification_method = state
        .service_verification_method("notary-key")
        .map_err(|error| error.to_string())?;
    let signing_key = state.notary_signing_key();
    match state
        .authority_commits()
        .freeze_account_realm_window(
            &request,
            &verification_method,
            signing_key.as_ref(),
            crate::wire::now(),
        )
        .await
    {
        Ok(Some(window)) => {
            let heads = std::iter::once(&window.window)
                .chain(window.additional_windows.iter())
                .map(|entry| arkret_wire::CommitStreamHead {
                    stream_ref: entry.stream_ref.clone(),
                    stream_position: entry.next_position - 1,
                    commit_id: entry.head_commit_ref.clone(),
                })
                .collect();
            let progress = AccountDetailProgress {
                window_cursor: window_cursor.clone(),
                expires_at_ms,
                retained_revision,
                governance_generation: window.governance_generation,
                stream_heads: heads,
                streams_limited: window.streams_limited,
            };
            Ok(Freeze::Window(
                Box::new(window_entry(
                    realm,
                    window,
                    window_cursor.as_str(),
                    baseline_revision,
                )),
                progress,
            ))
        }
        Ok(None) => Ok(Freeze::Unavailable(RealmDetailErrorCode::NotFound)),
        Err(coland_services::ServiceError::SchemaViolation(reason)) => {
            tracing::info!(%reason, realm_id = %realm, "Account window cannot be proved at this cut");
            Ok(Freeze::Unavailable(if reason.contains("byte budget") {
                RealmDetailErrorCode::LimitExceeded
            } else {
                RealmDetailErrorCode::TemporarilyUnavailable
            }))
        }
        Err(error)
            if error.conflict_code()
                == Some(coland_storage::ConflictCode::TemporarilyUnavailable) =>
        {
            Ok(Freeze::Unavailable(
                RealmDetailErrorCode::TemporarilyUnavailable,
            ))
        }
        Err(error) => Err(error.to_string()),
    }
}

/// Answer the requested Realm details before the account-global turn.
///
/// Returns `None` when no requested Realm owes a new window, so the global
/// channels get their turn. A newly frozen window is always delivered; an
/// `unavailable` answer is repeated only on a detail turn, so a Realm that
/// cannot be served never starves the global channels.
pub(super) async fn frame(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    body: &SyncRequestBody,
    after: &SyncCursor,
) -> Result<Option<AccountSubscribeFrame>, Box<arkret_wire::Problem>> {
    let Some(filter) = body.filter.as_ref() else {
        return Ok(None);
    };
    let realms = filter.realm_ids.clone().unwrap_or_default();
    if realms.is_empty() {
        return Ok(None);
    }
    let Some(session) = session else {
        return Ok(Some(control("unauthorized")));
    };
    let account = match crate::routing::identity::session_actor::session_actor_from_credential(
        state, session,
    ) {
        Ok(actor) => actor.as_account_id().cloned(),
        Err(_) => return Ok(Some(control("unauthorized"))),
    };
    let window_limit = filter
        .window_limit
        .unwrap_or(ACCOUNT_SYNC_DEFAULT_WINDOW_LIMIT);
    let report_unavailable = after.detail_turn || body.after.is_none();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let mut positions = after.detail_positions.clone();
    let mut entries = BTreeMap::new();
    let mut last_realm = None;
    let mut delivered_window = false;
    for realm in round_robin(realms, after.detail_next_realm.as_deref()) {
        let selection = realm_selection(filter, &realm);
        if selection == RealmSelection::NotSelected {
            continue;
        }
        let joined = match account.as_ref() {
            Some(account) if !is_realm_deleted(state, realm.as_str()).await => {
                match crate::routing::realm_state_snapshot::account_is_joined_member(
                    state,
                    realm.as_str(),
                    account,
                )
                .await
                {
                    Ok(joined) => joined,
                    Err(error) => {
                        tracing::warn!(%error, realm_id = %realm, "Account membership proof unavailable");
                        return Err(Box::new(continuation_unavailable()));
                    }
                }
            }
            _ => false,
        };
        let code = match (selection, account.as_ref()) {
            (RealmSelection::NotSelected, _) => continue,
            (RealmSelection::Default | RealmSelection::Explicit(_), None) => {
                Some(RealmDetailErrorCode::NotFound)
            }
            (RealmSelection::Default | RealmSelection::Explicit(_), Some(_)) if !joined => {
                Some(RealmDetailErrorCode::NotFound)
            }
            (selection, Some(account)) => {
                // Decide wakeups from this Account's proved visible set. A
                // newly joined Circle can establish position 0 without moving
                // the Realm head; unfiltered frontier activity may disclose
                // private stream existence through timing.
                let material = match state
                    .authority_commits()
                    .realm_state_snapshot_material_for_account(&realm, account)
                    .await
                {
                    Ok(Some(material)) => material,
                    Ok(None) => {
                        positions.remove(realm.as_str());
                        if report_unavailable {
                            entries.insert(
                                realm.to_string(),
                                unavailable(RealmDetailErrorCode::NotFound),
                            );
                            last_realm = Some(realm.to_string());
                        }
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(%error, realm_id = %realm, "Account visible stream heads unavailable");
                        return Err(Box::new(continuation_unavailable()));
                    }
                };
                let (selected_heads, streams_limited) =
                    selected_visible_heads(&material.visible_stream_heads, &realm, &selection);
                let delivered = positions.get(realm.as_str());
                if !needs_new_window(
                    delivered,
                    material.governance_generation,
                    &selected_heads,
                    streams_limited,
                    now_ms,
                ) {
                    continue;
                }
                let delivered_heads =
                    delivered.map_or_else(Vec::new, |progress| progress.stream_heads.clone());
                let selected_stream_refs = match selection {
                    RealmSelection::Explicit(refs) => Some(refs),
                    _ => None,
                };
                match freeze(
                    state,
                    account,
                    &realm,
                    window_limit,
                    delivered_heads,
                    selected_stream_refs,
                )
                .await
                {
                    Ok(Freeze::Window(entry, progress)) => {
                        positions.insert(realm.to_string(), progress);
                        entries.insert(realm.to_string(), *entry);
                        last_realm = Some(realm.to_string());
                        delivered_window = true;
                        // One atomic window per frame keeps every window
                        // inside the frame budget it was frozen against.
                        break;
                    }
                    Ok(Freeze::Unavailable(code)) => Some(code),
                    Err(error) => {
                        tracing::warn!(%error, realm_id = %realm, "Account window freeze failed");
                        return Err(Box::new(continuation_unavailable()));
                    }
                }
            }
        };
        if let Some(code) = code {
            positions.remove(realm.as_str());
            if report_unavailable {
                entries.insert(realm.to_string(), unavailable(code));
                last_realm = Some(realm.to_string());
            }
        }
    }
    if !delivered_window && !report_unavailable {
        return Ok(None);
    }
    if entries.is_empty() {
        return Ok(None);
    }
    let filter_value = sync_filter_value(body.filter.as_ref());
    let cursor = match cursor::sync_token_for_account_positions(
        state,
        Some(session),
        filter_value.as_ref(),
        after.positions.clone(),
        after.account_positions.clone(),
        after.to_device_position,
        after.account_summary_position,
        after.account_data_change_position,
        after.global_baseline.clone(),
        positions,
        false,
        last_realm,
    )
    .await
    {
        Ok(cursor) => cursor,
        Err(error) => {
            tracing::warn!(?error, "Realm detail continuation unavailable");
            return Err(Box::new(continuation_unavailable()));
        }
    };
    let frame = AccountSubscribeFrame {
        kind: AccountSubscribeFrameKind::Delta,
        cursor: Some(cursor),
        realms: Some(AccountSubscribeRealms { entries }),
        to_device: None,
        device_lists: None,
        account_data: None,
        agent_draft_pending_intents: None,
        notifications: None,
        partial: None,
        priority: None,
        reconnect_after_ms: None,
        realm_list: None,
        realm_list_changes: None,
        baseline: None,
        realm_invalidations: None,
    };
    if frame.validate().is_err()
        || arkret_canonical::canonical_json_bytes(&frame)
            .map_or(true, |bytes| bytes.len() > ACCOUNT_SYNC_MAX_FRAME_BYTES)
    {
        // The freeze budget must make this unreachable; never emit a frame
        // the closed contract or its byte bound would reject.
        tracing::error!("Realm detail frame failed its own closed contract");
        return Err(Box::new(continuation_unavailable()));
    }
    Ok(Some(frame))
}

fn continuation_unavailable() -> arkret_wire::Problem {
    arkret_wire::Problem::from_code(
        "temporarily_unavailable",
        "Account detail cut could not be proved",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm(seed: u8) -> RealmId {
        RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [seed; 32],
        ))
    }

    fn head(realm: &RealmId, position: u64, seed: u8) -> arkret_wire::CommitStreamHead {
        arkret_wire::CommitStreamHead {
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            stream_position: position,
            commit_id: arkret_wire::RealmCommitId::from_digest([seed; 32]),
        }
    }

    fn filter(value: Value) -> AccountFilter {
        let filter: AccountFilter = serde_json::from_value(value).unwrap();
        filter.validate().unwrap();
        filter
    }

    #[test]
    fn stream_selection_keeps_explicit_scopes() {
        let (a, b) = (realm(1), realm(2));
        let circle = arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [9; 32],
        ));
        let default = filter(json!({"realm_ids": [a, b]}));
        assert_eq!(realm_selection(&default, &a), RealmSelection::Default);
        let only_a = filter(json!({
            "realm_ids": [a, b],
            "stream_refs": [{"kind": "realm", "realm_id": a}],
        }));
        assert_eq!(
            realm_selection(&only_a, &a),
            RealmSelection::Explicit(vec![arkret_wire::CommitStreamRef::Realm {
                realm_id: a.clone()
            }])
        );
        assert_eq!(realm_selection(&only_a, &b), RealmSelection::NotSelected);
        let with_circle = filter(json!({
            "realm_ids": [a],
            "stream_refs": [
                {"kind": "realm", "realm_id": a},
                {"kind": "circle", "realm_id": a, "circle_id": circle},
            ],
        }));
        assert_eq!(
            realm_selection(&with_circle, &a),
            RealmSelection::Explicit(vec![
                arkret_wire::CommitStreamRef::Realm {
                    realm_id: a.clone()
                },
                arkret_wire::CommitStreamRef::Circle {
                    realm_id: a.clone(),
                    circle_id: circle
                },
            ])
        );
    }

    #[test]
    fn a_delivered_window_is_refrozen_on_generation_head_or_expiry_change() {
        let a = realm(1);
        let now = 1_000_000_000;
        let heads = vec![head(&a, 8, 3)];
        let progress = AccountDetailProgress {
            window_cursor: arkret_wire::Cursor::new("ak:cursor:window".to_owned()).unwrap(),
            expires_at_ms: now + WINDOW_TTL_MS,
            retained_revision: 4,
            governance_generation: 0,
            stream_heads: heads.clone(),
            streams_limited: false,
        };
        assert!(needs_new_window(None, 0, &heads, false, now));
        assert!(!needs_new_window(Some(&progress), 0, &heads, false, now));
        assert!(needs_new_window(Some(&progress), 1, &heads, false, now));
        assert!(needs_new_window(
            Some(&progress),
            0,
            &[head(&a, 9, 4)],
            false,
            now
        ));
        let circle = arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [9; 32],
        ));
        let circle_head = arkret_wire::CommitStreamHead {
            stream_ref: arkret_wire::CommitStreamRef::Circle {
                realm_id: a.clone(),
                circle_id: circle,
            },
            stream_position: 0,
            commit_id: arkret_wire::RealmCommitId::from_digest([10; 32]),
        };
        // A Circle self-join establishes a new visible stream without moving
        // the already delivered Realm head. The account-visible cut wakes it.
        let (selected, limited) = selected_visible_heads(
            &[heads[0].clone(), circle_head.clone()],
            &a,
            &RealmSelection::Default,
        );
        assert!(needs_new_window(
            Some(&progress),
            0,
            &selected,
            limited,
            now
        ));
        // An undisclosed Circle is absent from the account-visible material.
        let (selected, limited) = selected_visible_heads(&heads, &a, &RealmSelection::Default);
        assert!(!needs_new_window(
            Some(&progress),
            0,
            &selected,
            limited,
            now
        ));
        let (selected, limited) = selected_visible_heads(
            &[heads[0].clone(), circle_head.clone()],
            &a,
            &RealmSelection::Explicit(vec![circle_head.stream_ref.clone()]),
        );
        assert_eq!(selected, vec![circle_head]);
        assert!(needs_new_window(
            Some(&progress),
            0,
            &selected,
            limited,
            now
        ));
        assert!(needs_new_window(Some(&progress), 0, &heads, true, now));
        assert!(needs_new_window(
            Some(&progress),
            0,
            &heads,
            false,
            now + WINDOW_TTL_MS - WINDOW_RENEW_BEFORE_MS + 1,
        ));
    }

    #[test]
    fn detail_progress_is_closed_and_carries_the_retention_floor() {
        let a = realm(1);
        let progress = AccountDetailProgress {
            window_cursor: arkret_wire::Cursor::new("ak:cursor:window".to_owned()).unwrap(),
            expires_at_ms: 7,
            retained_revision: 4,
            governance_generation: 0,
            stream_heads: vec![head(&a, 8, 3)],
            streams_limited: false,
        };
        let value = serde_json::to_value(&progress).unwrap();
        assert_eq!(value["retained_revision"], 4);
        assert_eq!(value["governance_generation"], 0);
        let mut open = value.clone();
        open["timeline_limit"] = json!(20);
        assert!(serde_json::from_value::<AccountDetailProgress>(open).is_err());
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("retained_revision");
        assert!(serde_json::from_value::<AccountDetailProgress>(missing).is_err());
        let mut missing_generation = value;
        missing_generation
            .as_object_mut()
            .unwrap()
            .remove("governance_generation");
        assert!(serde_json::from_value::<AccountDetailProgress>(missing_generation).is_err());
    }

    #[test]
    fn round_robin_resumes_after_the_last_answered_realm() {
        let (a, b, c) = (realm(1), realm(2), realm(3));
        let mut sorted = vec![a.clone(), b.clone(), c.clone()];
        sorted.sort();
        let order = round_robin(sorted.clone(), Some(sorted[0].as_str()));
        assert_eq!(
            order,
            vec![sorted[1].clone(), sorted[2].clone(), sorted[0].clone()]
        );
        assert_eq!(
            round_robin(sorted.clone(), Some(sorted[2].as_str())),
            sorted
        );
        assert_eq!(round_robin(vec![c, a, b], None), sorted);
    }

    #[test]
    fn unavailable_details_are_exclusive_closed_entries() {
        let entry = serde_json::to_value(unavailable(RealmDetailErrorCode::TemporarilyUnavailable))
            .unwrap();
        assert_eq!(
            entry,
            json!({"unavailable": {"error_code": "temporarily_unavailable"}})
        );
    }
}
