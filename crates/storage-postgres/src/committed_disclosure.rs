//! Per-Event disclosure of committed rows on caller-scoped read surfaces.
//!
//! A surface that pairs a RealmCommit with its Event returns the closed
//! withheld branch `{commit, event_disclosure: {status: "withheld"}}` whenever
//! the caller may not receive the complete canonical bytes
//! (`service-http-binding.md` §3.1, `relation.md`). Every committed-event
//! surface applies the same decision, which on this Station withholds:
//!
//! - an Event that local retention expired (`retention_tombstones`);
//! - a Message create or revise whose Message has an `object_redaction` assertion, and an Event
//!   that an `ak:event:` redaction subject names, because redacted content must not stay
//!   recoverable from another read path (`strand-and-message.md` §9.2, `event-and-patch.md`
//!   §4.2.4). The typed current is the only redaction input; no Event history is rescanned.
//!
//! A joined member reading the Realm stream additionally receives another
//! actor's Event in full only when its kind is disclosed to every member
//! ([`crate::snapshot_disclosure_gate::DISCLOSED_EVENT_KINDS`]); every other
//! kind (moderator-only or otherwise unproved records) is withheld unless the
//! caller authored it.
//!
//! The Commit slot is always kept, so the caller's chain stays verifiable.
//! Withholding is never a reducer input and creates no new object.

use arkret_wire::{
    CommittedEventFullView, CommittedEventView, CommittedEventWithheldView, EventDisclosure,
    EventDisclosureStatus,
};

use super::{
    Array, AsyncPgConnection, PersistenceError, PersistenceResult, QueryableByName, RunQueryDsl,
    Text, sql_query,
};

#[derive(QueryableByName)]
struct WithheldRow {
    #[diesel(sql_type = Text)]
    commit_id: String,
}

/// Complete canonical private sources cannot be redacted in place. Keep the
/// existing PolicyRef author-only boundary and the controller's private
/// confirmation nonce out of ordinary member disclosure and peer fanout.
pub(crate) fn author_private_source(event: &arkret_wire::Event) -> bool {
    matches!(event.scope_ref, arkret_wire::ScopeRef::RealmControl { .. })
        || event.kind == arkret_wire::EventKind::AgentActionApprove
        || (event.kind == arkret_wire::EventKind::PolicyAction
            && event.payload.contains_key("policy_id"))
}

/// Read an original accepted Commit/Event pair on the caller's existing cut.
pub(crate) async fn accepted_full_event_in_connection(
    conn: &mut AsyncPgConnection,
    event_id: &arkret_wire::EventId,
) -> PersistenceResult<Option<CommittedEventFullView>> {
    use diesel::OptionalExtension;
    #[derive(QueryableByName)]
    struct Pair {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        commit_json: serde_json::Value,
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        envelope: serde_json::Value,
    }
    let token = crate::ids::parse_event_id(event_id.as_str())
        .ok_or_else(|| PersistenceError::SchemaViolation("Event id is not canonical".into()))?;
    let row = sql_query("SELECT c.commit_json,e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.state='committed'")
        .bind::<diesel::sql_types::Binary,_>(token.to_vec())
        .get_result::<Pair>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let full = CommittedEventFullView {
        commit: serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?,
        event: serde_json::from_value(row.envelope).map_err(PersistenceError::database)?,
    };
    if full.event.event_id != *event_id
        || full.commit.event_ref != *event_id
        || full.commit.realm_id != full.event.realm_id
        || full.commit.stream_ref.realm_id() != &full.event.realm_id
    {
        return Err(PersistenceError::Conflict(
            "revision_unavailable: accepted content pair differs".into(),
        ));
    }
    Ok(Some(full))
}

/// Decide canonical byte visibility after the caller's stream interval is proved.
pub(crate) async fn full_event_for_member_in_connection(
    conn: &mut AsyncPgConnection,
    row: &CommittedEventFullView,
    caller: &arkret_wire::ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<bool> {
    if matches!(
        row.commit.stream_ref,
        arkret_wire::CommitStreamRef::RealmControl { .. }
    ) {
        return Ok(false);
    }
    if ordinary_agent_read_ceiling(
        crate::account_stream_scan::realm_purpose(conn, &row.event.realm_id).await?,
    ) && let Some(controller) =
        crate::realm_authorization_cut::owned_controller_snapshot_in_connection(
            conn,
            &row.event.realm_id,
            caller,
            at,
        )
        .await?
    {
        let agent = caller.as_account_id().ok_or_else(|| {
            PersistenceError::Conflict("failed_precondition: Agent account unavailable".into())
        })?;
        let owner = controller.as_account_id().ok_or_else(|| {
            PersistenceError::Conflict("failed_precondition: controller account unavailable".into())
        })?;
        let circle = match &row.event.scope_ref {
            arkret_wire::ScopeRef::Circle { circle_id, .. } => Some(circle_id),
            _ => None,
        };
        let resources = crate::agent_management_admission::event_content_resources(&row.event)?;
        crate::agent_management_admission::require_content_snapshot_in_connection(
            conn,
            &row.event.realm_id,
            circle,
            owner,
            agent,
            arkret_models_collaboration::governance::operation_wire::AgentPolicyOperation::Read,
            arkret_wire::CapabilityActionId::EventRead,
            &resources,
            at,
        )
        .await?;
        if matches!(
            row.commit.stream_ref,
            arkret_wire::CommitStreamRef::Realm { .. }
        ) {
            let Some(floor) = crate::account_stream_scan::caller_realm_floor_in_connection(
                conn,
                &row.event.realm_id,
                &controller,
            )
            .await?
            else {
                return Ok(false);
            };
            if row.commit.stream_position < floor.oldest_position {
                return Ok(false);
            }
        }
        for recipient in [caller, &controller] {
            crate::realm_authorization_cut::RealmAuthorizationCut::read(
                conn,
                &row.event.realm_id,
                recipient,
            )
            .await?
            .require_membership_read_constraints_in_connection(conn, &row.event, at)
            .await?;
        }
        // Membership-derived visibility is intersected on the same bytes,
        // not replaced with an explicit event.read capability requirement.
        if !member_event_visible_in_connection(conn, row, &controller, at).await? {
            return Ok(false);
        }
    }
    member_event_visible_in_connection(conn, row, caller, at).await
}

pub(crate) fn ordinary_agent_read_ceiling(
    purpose: Option<arkret_models_collaboration::events_payloads::realm::RealmPurpose>,
) -> bool {
    use arkret_models_collaboration::events_payloads::realm::RealmPurpose;
    // Independent Direct and control Realms retain their dedicated read source.
    // An unknown role cannot exempt a known Agent from current evidence checks.
    !matches!(
        purpose,
        Some(
            RealmPurpose::DirectConversation
                | RealmPurpose::PrincipalControl
                | RealmPurpose::AgentControl
        )
    )
}

async fn member_event_visible_in_connection(
    conn: &mut AsyncPgConnection,
    row: &CommittedEventFullView,
    caller: &arkret_wire::ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<bool> {
    let event = &row.event;
    if matches!(
        event.kind,
        arkret_wire::EventKind::RelationCreate
            | arkret_wire::EventKind::RelationUpdate
            | arkret_wire::EventKind::RelationTombstone
    ) && !crate::relation_disclosure::event_visible_in_connection(conn, event, caller).await?
    {
        return Ok(false);
    }
    if let arkret_wire::ScopeRef::Sidecar { sidecar_id, .. } = &event.scope_ref
        && !crate::sidecar_access::participant_in_connection(
            conn,
            &event.realm_id,
            sidecar_id,
            caller,
        )
        .await?
        && !crate::sidecar_access::handshake_event_in_connection(conn, event, caller).await?
    {
        return Ok(false);
    }
    if author_private_source(event) {
        return Ok(&event.actor_id == caller);
    }
    if matches!(
        event.kind,
        arkret_wire::EventKind::SelfModerationReport
            | arkret_wire::EventKind::ModerationFrankingProof
    ) {
        let scope = if event.kind == arkret_wire::EventKind::ModerationFrankingProof {
            let proof: arkret_models_collaboration::events_payloads::moderation::FrankingProof =
                serde_json::from_value(
                    serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
                )
                .map_err(PersistenceError::database)?;
            crate::moderation_franking_proof_current_results::franking_target_scope_in_connection(
                conn,
                &event.realm_id,
                &proof.event_id,
            )
            .await?
        } else {
            event.scope_ref.clone()
        };
        let actions = [
            arkret_wire::CapabilityActionId::POLICY_MANAGE,
            arkret_wire::CapabilityActionId::MODERATION_DECISION,
        ];
        if crate::moderation_report_current_results::scope_moderator(
            conn,
            &event.realm_id,
            &scope,
            caller,
            &actions,
            at,
        )
        .await?
        {
            return Ok(true);
        }
        return crate::replica_authorization::scope_moderator(
            conn,
            &event.realm_id,
            caller,
            &scope,
            &actions,
            at,
        )
        .await;
    }
    let circle = if event.kind == arkret_wire::EventKind::CircleCreate {
        Some(arkret_wire::CircleId::from_event_id(&event.event_id))
    } else if let arkret_wire::ScopeRef::Circle { circle_id, .. } = &event.scope_ref {
        Some(circle_id.clone())
    } else {
        None
    };
    if let Some(circle_id) = circle {
        let Some(floor) = crate::account_stream_scan::caller_circle_floor_in_connection(
            conn,
            &event.realm_id,
            &circle_id,
            caller,
        )
        .await?
        else {
            return Ok(false);
        };
        if event.kind != arkret_wire::EventKind::CircleCreate
            && row.commit.stream_position < floor.oldest_position
        {
            return Ok(false);
        }
    }
    if event.kind == arkret_wire::EventKind::StrandWatchSet {
        let watch: arkret_models_collaboration::events_payloads::strand::StrandWatchSetPayload =
            serde_json::from_value(
                serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
            )
            .map_err(PersistenceError::database)?;
        // Ordinary scans carry no accepted watch-audit read pairing. A public
        // new value does not publish a private CAS preimage in canonical bytes.
        use arkret_models_collaboration::events_payloads::strand::StrandWatchLevel;
        let public = |level, level_public| {
            matches!(
                level,
                Some(StrandWatchLevel::All | StrandWatchLevel::Participating)
            ) && level_public == Some(true)
        };
        return Ok(&watch.watcher_actor_id == caller
            || (public(watch.level, watch.level_public)
                && watch.expected_value.as_ref().is_none_or(|previous| {
                    previous
                        .as_option()
                        .is_some_and(|value| public(Some(value.level), value.level_public))
                })));
    }
    Ok(&event.actor_id == caller
        || crate::snapshot_disclosure_gate::member_shared_event_kind(&event.kind))
}

/// Commits among `$1` whose Event this Station withholds.
pub(crate) const WITHHELD_COMMITS_SQL: &str = "\
    SELECT commit_row.commit_id FROM realm_commits commit_row \
    JOIN canonical_events event_row ON event_row.pk = commit_row.event_pk \
    CROSS JOIN LATERAL (SELECT CASE event_row.kind \
        WHEN 'ak.message.create' \
          THEN 'ak:message:' || substr(event_row.envelope->>'event_id', 10) \
        WHEN 'ak.message.revise' \
          THEN event_row.envelope->'payload'->>'message_id' \
      END AS message_id) target \
    WHERE commit_row.commit_id = ANY($1) \
      AND (EXISTS (SELECT 1 FROM retention_tombstones tombstone \
                   WHERE tombstone.event_id = event_row.id) \
        OR EXISTS (SELECT 1 FROM object_redaction_current_results redaction \
                   WHERE redaction.realm_id = event_row.realm_id \
                     AND redaction.target_ref IN (target.message_id, \
                                                  event_row.envelope->>'event_id')))";

/// Apply the committed-event disclosure decision to rows read at the caller's
/// cut, preserving their order and every Commit.
pub(crate) async fn disclose_in_connection(
    conn: &mut AsyncPgConnection,
    rows: Vec<CommittedEventFullView>,
) -> PersistenceResult<Vec<CommittedEventView>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let commit_ids = rows
        .iter()
        .map(|row| row.commit.commit_id.as_str().to_owned())
        .collect::<Vec<_>>();
    let withheld = withheld_commit_ids_in_connection(conn, &commit_ids).await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            if withheld.contains(row.commit.commit_id.as_str()) {
                CommittedEventView::Withheld(CommittedEventWithheldView {
                    commit: row.commit,
                    event_disclosure: EventDisclosure {
                        status: EventDisclosureStatus::Withheld,
                    },
                })
            } else {
                CommittedEventView::Full(row)
            }
        })
        .collect())
}

/// Reuse the canonical byte withdrawal decision for content current carriers
/// without fetching or disclosing their Event bytes.
pub(crate) async fn withheld_commit_ids_in_connection(
    conn: &mut AsyncPgConnection,
    commit_ids: &[String],
) -> PersistenceResult<std::collections::BTreeSet<String>> {
    if commit_ids.is_empty() {
        return Ok(Default::default());
    }
    Ok(sql_query(WITHHELD_COMMITS_SQL)
        .bind::<Array<Text>, _>(commit_ids)
        .load::<WithheldRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .into_iter()
        .map(|row| row.commit_id)
        .collect())
}

/// [`disclose_in_connection`] for a joined member of the Realm reading its
/// Realm stream: another actor's Event of a kind not disclosed to every
/// member is withheld as well.
pub(crate) async fn disclose_to_member_in_connection(
    conn: &mut AsyncPgConnection,
    rows: Vec<CommittedEventFullView>,
    caller: &arkret_wire::ActorId,
) -> PersistenceResult<Vec<CommittedEventView>> {
    let mut disclosed = Vec::with_capacity(rows.len());
    for item in disclose_in_connection(conn, rows).await? {
        let CommittedEventView::Full(row) = item else {
            disclosed.push(item);
            continue;
        };
        let full =
            full_event_for_member_in_connection(conn, &row, caller, chrono::Utc::now()).await?;
        disclosed.push(if full {
            CommittedEventView::Full(row)
        } else {
            CommittedEventView::Withheld(CommittedEventWithheldView {
                commit: row.commit,
                event_disclosure: EventDisclosure {
                    status: EventDisclosureStatus::Withheld,
                },
            })
        });
    }
    Ok(disclosed)
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::events_payloads::realm::RealmPurpose;

    use super::ordinary_agent_read_ceiling;

    #[test]
    fn collaboration_and_unknown_roles_do_not_bypass_agent_read_ceiling() {
        assert!(ordinary_agent_read_ceiling(Some(
            RealmPurpose::Collaboration
        )));
        assert!(ordinary_agent_read_ceiling(None));
        for purpose in [
            RealmPurpose::DirectConversation,
            RealmPurpose::PrincipalControl,
            RealmPurpose::AgentControl,
        ] {
            assert!(!ordinary_agent_read_ceiling(Some(purpose)));
        }
    }
}
