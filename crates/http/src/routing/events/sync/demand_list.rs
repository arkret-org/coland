use arkret_models_collaboration::sync_frames::demand_sync::*;

use super::*;

pub(crate) struct AccountSummaryDelta {
    pub page: Option<RealmListPage>,
    pub changes: Option<RealmListChanges>,
    pub invalidations: Option<Vec<RealmInvalidation>>,
    pub position: i64,
    pub initial_global_snapshot: Option<(i64, i64)>,
}

fn visible_item(row: &coland_storage::AccountSummaryVersion) -> Option<RealmListRow> {
    if !row.current_available {
        return None;
    }
    let membership = match (row.membership.as_deref(), row.current_membership.as_deref()) {
        (Some("join"), Some("join")) => RealmListMembership::Join,
        (Some("join" | "knock"), Some("knock")) | (Some("knock"), Some("join")) => {
            RealmListMembership::Knock
        }
        _ => return None,
    };
    Some(RealmListRow {
        realm_id: arkret_wire::RealmId::new(row.key.realm_id.clone()).ok()?,
        revision: u64::try_from(row.key.revision).ok()?,
        activity_position: u64::try_from(row.key.activity_position).ok()?,
        membership,
        title: (membership == RealmListMembership::Join)
            .then(|| row.title.clone())
            .flatten(),
        default_strand_id: (membership == RealmListMembership::Join)
            .then(|| row.default_strand_id.clone())
            .flatten()
            .and_then(|id| arkret_wire::StrandId::new(id).ok()),
    })
}

pub(crate) async fn read(
    state: &AppState,
    session: &SessionIdentityState,
    body: &SyncRequestBody,
    after: &SyncCursor,
) -> Result<AccountSummaryDelta, global_channels::GlobalReadError> {
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, session)
            .map_err(|_| "invalid account actor".to_owned())?;
    let actor_key = actor.canonical_key().map_err(|error| error.to_string())?;
    // A resumable Realm-detail turn can precede the first account baseline.
    // Its cursor has no summary cut yet, even though `after` is present.
    let initial = body.after.is_none() || after.global_baseline.is_none();
    let mut position = after.account_summary_position;
    let mut page = None;
    let mut initial_global_snapshot = None;
    if initial || body.realm_list.is_some() {
        let request = body.realm_list.clone().unwrap_or_default();
        request.validate().map_err(|e| e.to_string())?;
        let frozen = if let Some(token) = &request.after {
            cursor::parse_realm_list_cursor(state, session, token.as_str())
                .await
                .map_err(global_channels::GlobalReadError::from)?
        } else {
            let (watermark, global_watermark) = state
                .sync()
                .account_sync_watermarks()
                .await
                .map_err(|e| e.to_string())?;
            cursor::RealmListPosition {
                watermark,
                global_watermark,
                expires_at_ms: chrono::Utc::now().timestamp_millis() + 3_600_000,
                after: None,
                snapshot_cursor: None,
            }
        };
        if initial {
            position = frozen.watermark;
            initial_global_snapshot = Some((frozen.global_watermark, frozen.expires_at_ms));
        }
        let snapshot_cursor = cursor::realm_list_token(
            state,
            session,
            &cursor::RealmListPosition {
                watermark: frozen.watermark,
                global_watermark: frozen.global_watermark,
                expires_at_ms: frozen.expires_at_ms,
                after: None,
                snapshot_cursor: frozen.snapshot_cursor.clone(),
            },
        )
        .await
        .map_err(global_channels::GlobalReadError::from)?;
        let mut scanned = frozen.after.clone();
        let mut items = Vec::new();
        let limit = request.limit.unwrap_or(20) as usize;
        let complete = loop {
            let rows = state
                .sync()
                .account_summary_page(&actor_key, frozen.watermark, scanned.as_ref(), 200)
                .await
                .map_err(|e| e.to_string())?;
            let mut consumed = 0;
            for row in &rows {
                let item = (row.key.revision <= frozen.watermark
                    && row.valid_until.is_none_or(|end| end > frozen.watermark))
                .then(|| visible_item(row))
                .flatten();
                if let Some(item) = item {
                    if items.len() >= limit {
                        break;
                    }
                    item.validate().map_err(|e| e.to_string())?;
                    items.push(item);
                }
                consumed += 1;
                scanned = Some(row.key.clone());
            }
            let complete = consumed == rows.len() && rows.len() < 200;
            // A page with next_cursor must have at least one visible item.
            // Keep scanning frozen rows when a whole storage batch is hidden.
            if complete || !items.is_empty() {
                break complete;
            }
        };
        let next_cursor = if complete {
            None
        } else {
            Some(
                cursor::realm_list_token(
                    state,
                    session,
                    &cursor::RealmListPosition {
                        watermark: frozen.watermark,
                        global_watermark: frozen.global_watermark,
                        expires_at_ms: frozen.expires_at_ms,
                        after: scanned,
                        snapshot_cursor: Some(snapshot_cursor.clone()),
                    },
                )
                .await
                .map_err(global_channels::GlobalReadError::from)?,
            )
        };
        page = Some(RealmListPage {
            snapshot_cursor: snapshot_cursor.to_string(),
            snapshot_revision: frozen.watermark as u64,
            items,
            next_cursor: next_cursor.map(|cursor| cursor.to_string()),
        });
    }
    // Read a lower bound before scanning. When the bounded scan is exhausted,
    // every summary revision through this cut was considered, including holes
    // created by current-result publications in the shared revision domain.
    let observed_cut = state
        .sync()
        .account_summary_watermark()
        .await
        .map_err(|e| e.to_string())?;
    let rows = state
        .sync()
        .account_summary_changes(&actor_key, position, 100)
        .await
        .map_err(|e| e.to_string())?;
    let exhausted = rows.len() < 100;
    let mut latest = BTreeMap::new();
    let mut invalidated = BTreeMap::new();
    for row in rows {
        position = position.max(row.key.revision);
        if row.invalidated {
            invalidated.insert(row.key.realm_id.clone(), row.key.revision);
        }
        latest.insert(row.key.realm_id.clone(), row);
    }
    if exhausted {
        position = position.max(observed_cut);
    }
    let mut upserts = Vec::new();
    let mut removals = Vec::new();
    for (realm, row) in latest {
        if let Some(item) = visible_item(&row) {
            upserts.push(item);
        } else if row.current_membership.is_none() {
            removals.push(RealmListRemoval {
                realm_id: arkret_wire::RealmId::new(realm).map_err(|e| e.to_string())?,
                revision: row.key.revision as u64,
            });
        }
    }
    upserts.sort_by_key(|item| (item.revision, item.realm_id.clone()));
    removals.sort_by_key(|item| (item.revision, item.realm_id.clone()));
    let mut invalidations = invalidated
        .into_iter()
        .map(|(realm, revision)| {
            Ok(RealmInvalidation {
                realm_id: arkret_wire::RealmId::new(realm).map_err(|e| e.to_string())?,
                revision: revision as u64,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    invalidations.sort_by_key(|item| (item.revision, item.realm_id.clone()));
    Ok(AccountSummaryDelta {
        page,
        initial_global_snapshot,
        changes: (!upserts.is_empty() || !removals.is_empty())
            .then_some(RealmListChanges { upserts, removals }),
        invalidations: (!invalidations.is_empty()).then_some(invalidations),
        position,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_join_never_discloses_private_fields_after_knock_or_revocation() {
        let mut row = coland_storage::AccountSummaryVersion {
            key: coland_storage::AccountSummaryKey {
                realm_id: "ak:realm:AQVZRUJrSSC16EodjmqL6mBFC9TGwv6oxx-sQlJzlvxS".to_owned(),
                revision: 1,
                activity_position: 1,
            },
            membership: Some("join".to_owned()),
            title: Some("private title".to_owned()),
            default_strand_id: None,
            valid_until: Some(2),
            current_membership: Some("knock".to_owned()),
            current_available: true,
            invalidated: false,
        };
        let item = visible_item(&row).unwrap();
        assert_eq!(item.membership, RealmListMembership::Knock);
        assert!(item.title.is_none());
        row.current_membership = None;
        assert!(visible_item(&row).is_none());
        row.current_membership = Some("join".to_owned());
        row.current_available = false;
        assert!(visible_item(&row).is_none());
    }
}
