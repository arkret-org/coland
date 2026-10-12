use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountDataContainer, AccountSubscribeDeviceListChanges, AgentDraftPendingIntent,
    AgentDraftPendingIntentChange, AgentDraftPendingIntentContainer,
    AgentDraftPendingIntentRemoval, NotificationContainer, StationCasAccountDataContainer,
    StationCasAccountDataRemoval,
};
use arkret_models_collaboration::sync_frames::demand_sync::{
    AccountBaselineChannel, AccountBaselineSegment,
};

use super::*;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GlobalProgress {
    snapshot_cursor: arkret_wire::Cursor,
    snapshot_watermark: i64,
    snapshot_expires_at_ms: i64,
    offsets: BTreeMap<String, String>,
    completed: BTreeSet<String>,
    positions: BTreeMap<String, i64>,
    #[serde(default)]
    pending_snapshot_cut_position: Option<i64>,
    #[serde(default)]
    pending_page_offset: u64,
    #[serde(default)]
    pending_projection_position: i64,
}

pub(crate) struct GlobalDelta {
    pub context: Value,
    pub baseline: Option<AccountBaselineSegment>,
    pub account_data: AccountDataContainer,
    pub notifications: NotificationContainer,
    pub device_lists: AccountSubscribeDeviceListChanges,
    pub agent_draft_pending_intents: Option<AgentDraftPendingIntentContainer>,
}

#[derive(Debug)]
pub(crate) enum GlobalReadError {
    ResyncRequired,
    Cursor(SyncCursorError),
    Unavailable(String),
}

impl From<String> for GlobalReadError {
    fn from(message: String) -> Self {
        Self::Unavailable(message)
    }
}

impl From<&str> for GlobalReadError {
    fn from(message: &str) -> Self {
        Self::Unavailable(message.to_owned())
    }
}

impl From<SyncCursorError> for GlobalReadError {
    fn from(error: SyncCursorError) -> Self {
        Self::Cursor(error)
    }
}

pub(super) fn pending_intents_allowed(has_agent_session: bool, has_account_binding: bool) -> bool {
    !has_agent_session && has_account_binding
}

fn global_baseline_complete(progress: &GlobalProgress, pending_allowed: bool) -> bool {
    global_baseline_complete_channels(&progress.completed, pending_allowed)
}

pub(super) fn global_baseline_complete_channels(
    completed: &BTreeSet<String>,
    pending_allowed: bool,
) -> bool {
    let mut required = vec![
        "account_data_events",
        "station_cas",
        "notifications",
        "device_lists",
    ];
    if pending_allowed {
        required.push("agent_draft_pending_intents");
    }
    required
        .into_iter()
        .all(|channel| completed.contains(channel))
}

pub(crate) async fn read(
    state: &AppState,
    session: &SessionIdentityState,
    after: &SyncCursor,
    initial_snapshot: Option<(i64, i64)>,
) -> Result<GlobalDelta, GlobalReadError> {
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
            .map_err(|_| "invalid account actor".to_owned())?;
    let actor_key = actor.canonical_key().map_err(|error| error.to_string())?;
    // Authentication already revalidates the human device authorization on
    // every request. Agent and recovery credentials must not receive this
    // controller-holder-private projection.
    let pending_allowed = pending_intents_allowed(
        session.agent_session().is_some(),
        session.account_pk.is_some(),
    );
    let watermark = state
        .sync()
        .account_global_watermark()
        .await
        .map_err(|error| error.to_string())?;
    let mut progress = if let Some(context) = &after.global_baseline {
        serde_json::from_value::<GlobalProgress>(context.clone())
            .map_err(|error| error.to_string())?
    } else {
        GlobalProgress {
            snapshot_cursor: arkret_wire::Cursor::new(format!(
                "ak:cursor:{}",
                uuid::Uuid::now_v7().simple()
            ))
            .map_err(|error| error.to_string())?,
            snapshot_watermark: initial_snapshot.map_or(watermark, |(cut, _)| cut),
            snapshot_expires_at_ms: initial_snapshot.map_or_else(
                || chrono::Utc::now().timestamp_millis() + 3_600_000,
                |(_, deadline)| deadline,
            ),
            offsets: BTreeMap::new(),
            completed: BTreeSet::new(),
            positions: BTreeMap::new(),
            pending_snapshot_cut_position: None,
            pending_page_offset: 0,
            pending_projection_position: 0,
        }
    };
    if !global_baseline_complete(&progress, pending_allowed)
        && progress.snapshot_expires_at_ms <= chrono::Utc::now().timestamp_millis()
    {
        return Err(GlobalReadError::ResyncRequired);
    }
    let mut account_data = AccountDataContainer::default();
    let mut cas = StationCasAccountDataContainer::default();
    let mut notifications = NotificationContainer::default();
    let mut device_lists = AccountSubscribeDeviceListChanges {
        changed_ids: Vec::new(),
        left_ids: Vec::new(),
    };
    let mut agent_draft_pending_intents = None;
    let mut channels = Vec::new();
    let mut completed_channels = Vec::new();
    let mut remaining_bytes = 6 * 1024 * 1024;
    let mut channel_defs = vec![
        (
            "account_data_events",
            AccountBaselineChannel::AccountDataEvents,
        ),
        ("station_cas", AccountBaselineChannel::StationCas),
        ("notifications", AccountBaselineChannel::Notifications),
        ("device_lists", AccountBaselineChannel::DeviceLists),
    ];
    if pending_allowed {
        channel_defs.push((
            "agent_draft_pending_intents",
            AccountBaselineChannel::AgentDraftPendingIntents,
        ));
        if progress.pending_snapshot_cut_position.is_none() {
            progress.pending_snapshot_cut_position = Some(
                state
                    .sync()
                    .account_global_channel_position(
                        &actor_key,
                        "agent_draft_pending_intents",
                        progress.snapshot_watermark,
                    )
                    .await
                    .map_err(|error| error.to_string())?,
            );
        }
    }
    for (name, channel) in channel_defs {
        let baseline = !progress.completed.contains(name);
        let cut = if baseline {
            progress.snapshot_watermark
        } else {
            watermark
        };
        let position = progress
            .positions
            .get(name)
            .copied()
            .unwrap_or(progress.snapshot_watermark);
        let offset = progress.offsets.get(name).cloned().unwrap_or_default();
        let rows = state
            .sync()
            .account_global_page(
                &actor_key,
                name,
                cut,
                &offset,
                (!baseline).then_some(position),
                101,
            )
            .await
            .map_err(|error| error.to_string())?;
        let mut consumed = 0usize;
        let mut by_key = BTreeMap::new();
        let mut pending_items = Vec::new();
        let pending_page_offset = progress.pending_page_offset;
        for row in &rows {
            if row.payload.get("_oversized").and_then(Value::as_bool) == Some(true) {
                return Err("one account-global value exceeds the byte budget".into());
            }
            if row.payload.get("_budget_boundary").is_some() {
                break;
            }
            if consumed >= 100 {
                break;
            }
            let mut payload = row.payload.clone();
            let mut bytes = arkret_canonical::canonical_json_bytes(&payload)
                .map_err(|error| error.to_string())?
                .len()
                + 256;
            if bytes > remaining_bytes
                && name == "notifications"
                && payload.get("action").and_then(Value::as_str) == Some("upsert")
                && payload
                    .get_mut("data")
                    .and_then(Value::as_object_mut)
                    .is_some_and(|data| data.remove("preview").is_some())
            {
                bytes = arkret_canonical::canonical_json_bytes(&payload)
                    .map_err(|error| error.to_string())?
                    .len()
                    + 256;
            }
            if bytes > remaining_bytes {
                if consumed == 0 && remaining_bytes == 6 * 1024 * 1024 {
                    return Err("account global item exceeds frame byte budget".into());
                }
                break;
            }
            remaining_bytes -= bytes;
            consumed += 1;
            if baseline {
                progress
                    .offsets
                    .insert(name.to_owned(), row.item_key.clone());
            } else {
                progress.positions.insert(name.to_owned(), row.revision);
            }
            if name == "agent_draft_pending_intents" {
                let change = if row.deleted {
                    AgentDraftPendingIntentChange::Remove(
                        serde_json::from_value::<AgentDraftPendingIntentRemoval>(payload)
                            .map_err(|error| error.to_string())?,
                    )
                } else {
                    AgentDraftPendingIntentChange::Upsert(
                        serde_json::from_value::<AgentDraftPendingIntent>(payload)
                            .map_err(|error| error.to_string())?,
                    )
                };
                pending_items.push(change);
                if !baseline {
                    progress.pending_projection_position = row.channel_position;
                }
            } else {
                by_key.insert(row.item_key.clone(), (row.deleted, payload));
            }
        }
        let terminal_page = consumed == rows.len() && rows.len() < 101;
        if baseline {
            channels.push(channel);
            if name == "agent_draft_pending_intents" {
                progress.pending_page_offset =
                    progress.pending_page_offset.saturating_add(consumed as u64);
                if terminal_page {
                    progress.pending_projection_position =
                        progress.pending_snapshot_cut_position.unwrap_or_default();
                }
                agent_draft_pending_intents = Some(AgentDraftPendingIntentContainer::Baseline {
                    snapshot_cut_position: u64::try_from(
                        progress.pending_snapshot_cut_position.unwrap_or_default(),
                    )
                    .map_err(|_| "pending snapshot position is negative")?,
                    page_offset: pending_page_offset,
                    next_page_offset: (!terminal_page).then_some(progress.pending_page_offset),
                    items: pending_items,
                });
            }
            if terminal_page {
                progress.completed.insert(name.to_owned());
                progress.positions.insert(name.to_owned(), cut);
                progress.offsets.remove(name);
                completed_channels.push(channel);
            }
        } else {
            if name == "agent_draft_pending_intents" && !pending_items.is_empty() {
                agent_draft_pending_intents = Some(AgentDraftPendingIntentContainer::Delta {
                    projection_position: u64::try_from(progress.pending_projection_position)
                        .map_err(|_| "pending projection position is negative")?,
                    items: pending_items,
                });
            }
            if terminal_page {
                progress.positions.insert(name.to_owned(), cut);
            }
        }
        for (deleted, payload) in by_key.into_values() {
            if baseline && deleted {
                continue;
            }
            match name {
                "account_data_events" => {
                    if payload["source"] == "invalidated" {
                        return Err(GlobalReadError::ResyncRequired);
                    }
                    let event: arkret_wire::Event =
                        serde_json::from_value(payload["value"].clone())
                            .map_err(|error| error.to_string())?;
                    let key = event
                        .payload
                        .get("key")
                        .and_then(Value::as_str)
                        .ok_or("account data key absent")?;
                    if event.actor_id!=actor || crate::routing::identity::account_data::is_service_internal_account_data_key(key) || (session.agent_session().is_some() && crate::routing::identity::account_data::is_controller_private_account_data_key(key)) {continue;}
                    account_data.events.push(event);
                }

                "station_cas" => {
                    let key = payload["account_data_key"]
                        .as_str()
                        .ok_or("CAS key absent")?;
                    if !crate::routing::identity::account_data::is_station_cas_account_data_key(key)
                    {
                        continue;
                    }
                    let revision = payload["revision"].as_u64().ok_or("CAS revision absent")?;
                    let updated_at = serde_json::from_value(payload["updated_at"].clone())
                        .map_err(|error| error.to_string())?;
                    if deleted {
                        cas.removals.push(StationCasAccountDataRemoval {
                            account_data_key: key.to_owned(),
                            revision,
                            updated_at,
                        });
                    } else {
                        cas.upserts
                            .push(arkret_models_identity::account::AccountDataRow {
                                account_data_key: key.to_owned(),
                                revision,
                                content: payload["payload"].clone(),
                                updated_at,
                            });
                    }
                }
                "notifications" => notifications
                    .items
                    .push(serde_json::from_value(payload).map_err(|error| error.to_string())?),
                "device_lists" => {
                    let owner =
                        serde_json::from_value(payload).map_err(|error| error.to_string())?;
                    if deleted {
                        device_lists.left_ids.push(owner);
                    } else {
                        device_lists.changed_ids.push(owner);
                    }
                }
                "agent_draft_pending_intents" => unreachable!("handled in channel order"),
                _ => unreachable!(),
            }
        }
    }
    if !cas.upserts.is_empty()
        || !cas.removals.is_empty()
        || channels.contains(&AccountBaselineChannel::StationCas)
    {
        account_data.station_cas = Some(cas);
    }
    let baseline = (!channels.is_empty()).then(|| AccountBaselineSegment {
        snapshot_cursor: progress.snapshot_cursor.to_string(),
        channels,
        completed_channels,
    });
    if let Some(container) = &agent_draft_pending_intents {
        container.validate().map_err(|error| error.to_string())?;
    }
    Ok(GlobalDelta {
        context: serde_json::to_value(progress).map_err(|error| error.to_string())?,
        baseline,
        account_data,
        notifications,
        device_lists,
        agent_draft_pending_intents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress(completed: &[&str]) -> GlobalProgress {
        GlobalProgress {
            snapshot_cursor: arkret_wire::Cursor::new("ak:cursor:01964137000070008000000000000001")
                .unwrap(),
            snapshot_watermark: 7,
            snapshot_expires_at_ms: 9,
            offsets: BTreeMap::new(),
            completed: completed.iter().map(|value| (*value).to_owned()).collect(),
            positions: BTreeMap::new(),
            pending_snapshot_cut_position: Some(11),
            pending_page_offset: 100,
            pending_projection_position: 11,
        }
    }

    #[test]
    fn pending_channel_requires_a_human_account_holder() {
        assert!(pending_intents_allowed(false, true));
        assert!(!pending_intents_allowed(true, true));
        assert!(!pending_intents_allowed(false, false));
    }

    #[test]
    fn fifth_channel_participates_in_resync_completion_only_for_its_audience() {
        let four = progress(&[
            "account_data_events",
            "station_cas",
            "notifications",
            "device_lists",
        ]);
        assert!(global_baseline_complete(&four, false));
        assert!(!global_baseline_complete(&four, true));
        let five = progress(&[
            "account_data_events",
            "station_cas",
            "notifications",
            "device_lists",
            "agent_draft_pending_intents",
        ]);
        assert!(global_baseline_complete(&five, true));
    }

    #[test]
    fn legacy_cursor_context_defaults_private_channel_progress() {
        let value = serde_json::json!({
            "snapshot_cursor": "ak:cursor:01964137000070008000000000000001",
            "snapshot_watermark": 7,
            "snapshot_expires_at_ms": 9,
            "offsets": {},
            "completed": [],
            "positions": {}
        });
        let decoded: GlobalProgress = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.pending_snapshot_cut_position, None);
        assert_eq!(decoded.pending_page_offset, 0);
        assert_eq!(decoded.pending_projection_position, 0);
    }

    #[test]
    fn cursor_context_serializes_private_offsets_without_exposing_them_in_the_dto() {
        let encoded = serde_json::to_value(progress(&[])).unwrap();
        assert_eq!(encoded["pending_snapshot_cut_position"], 11);
        assert_eq!(encoded["pending_page_offset"], 100);
        assert_eq!(encoded["pending_projection_position"], 11);
    }

    #[test]
    fn terminal_private_baseline_page_serializes_with_fifth_channel_completion() {
        use arkret_models_collaboration::sync_frames::account_subscribe::{
            AccountSubscribeFrame, AccountSubscribeFrameKind,
        };

        let channel = AccountBaselineChannel::AgentDraftPendingIntents;
        let frame = AccountSubscribeFrame {
            kind: AccountSubscribeFrameKind::Delta,
            cursor: Some("ak:cursor:01964137000070008000000000000001".to_owned()),
            realms: None,
            to_device: None,
            device_lists: None,
            account_data: None,
            agent_draft_pending_intents: Some(AgentDraftPendingIntentContainer::Baseline {
                snapshot_cut_position: 11,
                page_offset: 100,
                next_page_offset: None,
                items: Vec::new(),
            }),
            notifications: None,
            partial: None,
            priority: None,
            reconnect_after_ms: None,
            realm_list: None,
            realm_list_changes: None,
            baseline: Some(AccountBaselineSegment {
                snapshot_cursor: "ak:cursor:01964137000070008000000000000001".to_owned(),
                channels: vec![channel],
                completed_channels: vec![channel],
            }),
            realm_invalidations: None,
        };
        frame.validate().unwrap();
        let encoded = serde_json::to_value(frame).unwrap();
        assert_eq!(encoded["agent_draft_pending_intents"]["mode"], "baseline");
        assert_eq!(
            encoded["baseline"]["completed_channels"][0],
            "agent_draft_pending_intents"
        );
    }
}
