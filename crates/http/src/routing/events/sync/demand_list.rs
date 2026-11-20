use arkret_models_collaboration::sync_frames::demand_sync::*;

use super::*;

pub(crate) struct AccountSummaryDelta {
    pub page: Option<RealmListPage>,
    pub changes: Option<RealmListChanges>,
    pub invalidations: Option<Vec<RealmInvalidation>>,
    pub position: i64,
    pub agent_disclosures: Option<BTreeSet<String>>,
    pub initial_global_snapshot: Option<(i64, i64)>,
}

fn visible_item(row: &coland_storage::AccountSummaryVersion) -> Option<AccountRealmView> {
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
    Some(AccountRealmView {
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

fn list_item(
    row: &coland_storage::AccountSummaryVersion,
    agent: Option<&coland_services::identity::AgentSessionState>,
) -> Option<AccountRealmView> {
    let mut item = visible_item(row)?;
    if let Some(agent) = agent {
        let details = agent.metadata.scope_details.as_ref()?;
        if row.valid_until.is_some()
            || item.membership != RealmListMembership::Join
            || !details.realm_ids.is_empty() && !details.realm_ids.contains(&item.realm_id)
            || !details.resources.realm_ids.is_empty()
                && !details.resources.realm_ids.contains(&item.realm_id)
            || details.realm_ids.is_empty() && !details.strand_ids.is_empty()
            || details.resources.realm_ids.is_empty() && !details.resources.strand_ids.is_empty()
        {
            return None;
        }
        item.title = None;
        item.default_strand_id = None;
        item.revision = item.activity_position;
    }
    Some(item)
}

pub(crate) async fn read(
    state: &AppState,
    session: &SessionIdentityState,
    body: &AccountSubscribeParameters,
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
    let agent = session.agent_session();
    let mut disclosures: Option<BTreeSet<String>> = if agent.is_some() {
        Some(match after.global_baseline.as_ref() {
            Some(context) => serde_json::from_value(context["agent_memberships"].clone())
                .map_err(|_| "invalid membership continuation")?,
            None => BTreeSet::new(),
        })
    } else {
        None
    };
    let mut page = None;
    let mut initial_global_snapshot = None;
    if initial || body.realm_list_parameters.is_some() {
        let request = body.realm_list_parameters.clone().unwrap_or_default();
        request.validate().map_err(|e| e.to_string())?;
        let mut frozen = if let Some(token) = &request.after {
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
                visible_revision: None,
                snapshot_cursor: None,
            }
        };
        if initial {
            position = frozen.watermark;
            initial_global_snapshot = Some((frozen.global_watermark, frozen.expires_at_ms));
        }
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
                .then(|| list_item(row, agent))
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
            // Only an additional visible row proves that another page exists.
            if complete || consumed < rows.len() {
                break complete;
            }
        };
        if let Some(seen) = disclosures.as_mut() {
            seen.extend(items.iter().map(|item| item.realm_id.to_string()));
            frozen
                .visible_revision
                .get_or_insert_with(|| items.first().map_or(0, |item| item.revision));
        }
        let snapshot_cursor = cursor::realm_list_token(
            state,
            session,
            &cursor::RealmListPosition {
                watermark: frozen.watermark,
                global_watermark: frozen.global_watermark,
                expires_at_ms: frozen.expires_at_ms,
                after: None,
                visible_revision: frozen.visible_revision,
                snapshot_cursor: frozen.snapshot_cursor.clone(),
            },
            &after.input_authorities,
        )
        .await
        .map_err(global_channels::GlobalReadError::from)?;
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
                        visible_revision: frozen.visible_revision,
                        snapshot_cursor: Some(snapshot_cursor.clone()),
                    },
                    &after.input_authorities,
                )
                .await
                .map_err(global_channels::GlobalReadError::from)?,
            )
        };
        page = Some(RealmListPage {
            snapshot_cursor: snapshot_cursor.to_string(),
            snapshot_revision: frozen.visible_revision.unwrap_or(frozen.watermark as u64),
            items,
            next_cursor: next_cursor.map(|cursor| cursor.to_string()),
        });
    }
    // Read a lower bound before scanning. When the bounded scan is exhausted,
    // every summary revision through this cut was considered, including holes
    // created by current-state publications in the shared revision domain.
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
        if row.invalidated && agent.is_none() {
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
        if let Some(item) = list_item(&row, agent) {
            if let Some(seen) = disclosures.as_mut() {
                seen.insert(realm.clone());
            }
            upserts.push(item);
        } else if (row.current_membership.is_none()
            || agent.is_some()
                && (!row.current_available || row.current_membership.as_deref() != Some("join")))
            && disclosures.as_mut().is_none_or(|seen| seen.remove(&realm))
        {
            removals.push(RealmListRemoval {
                realm_id: arkret_wire::RealmId::new(realm).map_err(|e| e.to_string())?,
                revision: if agent.is_some() {
                    row.key.activity_position
                } else {
                    row.key.revision
                } as u64,
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
        agent_disclosures: disclosures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agent_membership_list_uses_current_join_and_the_session_disclosure_ceiling() {
        let mut agent = coland_services::identity::AgentSessionState {
            metadata: crate::routing::identity::auth_grant_dpop::tests::test_agent_metadata(&[
                arkret_wire::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1,
            ]),
            freshness_state: arkret_wire::FreshnessState::Fresh,
        };
        let mut row = coland_storage::AccountSummaryVersion {
            key: coland_storage::AccountSummaryKey {
                realm_id: super::super::tests::ROSTER_REALM.to_owned(),
                revision: 27,
                activity_position: 2,
            },
            membership: Some("join".into()),
            current_membership: Some("join".into()),
            title: Some("private title".into()),
            default_strand_id: Some(
                "ak:strand:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            ),
            current_available: true,
            valid_until: None,
            invalidated: false,
        };
        let item = list_item(&row, Some(&agent)).unwrap();
        assert_eq!(item.revision, 2);
        assert!(item.title.is_none() && item.default_strand_id.is_none());
        row.valid_until = Some(31);
        assert!(list_item(&row, Some(&agent)).is_none());
        row.valid_until = None;
        row.current_membership = None;
        assert!(list_item(&row, Some(&agent)).is_none());
        row.current_membership = Some("knock".into());
        assert!(list_item(&row, Some(&agent)).is_none());
        row.current_membership = Some("join".into());
        agent
            .metadata
            .scope_details
            .as_mut()
            .unwrap()
            .resources
            .realm_ids
            .push(
                arkret_wire::RealmId::new("ak:realm:AQVZRUJrSSC16EodjmqL6mBFC9TGwv6oxx-sQlJzlvxS")
                    .unwrap(),
            );
        assert!(list_item(&row, Some(&agent)).is_none());
    }

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
