//! The `message_reactions` typed current writer at the accepting RealmCommit
//! cut.
//!
//! The complete value contains only active `(full actor, key, source)`
//! entries. An add replaces its own business key and a remove deletes that
//! key. Empty values retain the accepting Commit revision. History scans and
//! partial pages never enter this writer; replicas require an installed cut
//! followed by the next consecutive Commit.
//!
//! Admission (section 9.8.2 / 9.8.4): the actor holds `ak.reaction.add` or
//! `ak.reaction.remove` at the same cut, the target is an accepted
//! `ak:message:` of this Realm signed in the exact scope of the reaction, and
//! the scope's MLS send gate (`mls_group_current_states`) admits the carrier.
//! A target this Station has not materialized is `dependency_missing` with
//! zero writes.

use arkret_models_collaboration::events_payloads::reaction::{
    MessageReactionsCurrentValue, ReactionCurrentEntry, ReactionPayload,
};
use coland_storage::{ConflictCode, PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::Value;

#[derive(diesel::QueryableByName)]
struct ReactionSetRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Jsonb)]
    source_stream_ref: Value,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

fn conflict(code: ConflictCode, detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{code}: {detail}"))
}

fn corrupt(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!("stored message_reactions is invalid: {detail}"))
}

/// The complete typed payload of a reaction Event whose target is an
/// `ak:message:` (section 9.8.2: every other target kind is an active
/// `schema_violation` in v1 core).
fn reaction_payload(
    event: &arkret_wire::Event,
) -> PersistenceResult<(ReactionPayload, arkret_wire::MessageId)> {
    let payload: ReactionPayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let message_id = arkret_wire::MessageId::new(payload.target_ref.as_str()).map_err(|_| {
        PersistenceError::SchemaViolation("a v1 core reaction targets an ak:message:".to_owned())
    })?;
    Ok((payload, message_id))
}

/// Admit one reaction at the governing Station's accepting cut.
async fn admit_reaction_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    message_id: &arkret_wire::MessageId,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.executed_by.is_some() || event.applet_id.is_some() {
        return Err(conflict(
            ConflictCode::FailedPrecondition,
            "a delegated reaction producer needs its own admission cut",
        ));
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
        conn, event, commit, prepared,
    )
    .await?;
    if matches!(event.scope_ref, arkret_wire::ScopeRef::Circle { .. }) {
        crate::circle_current_states::require_active_author_in_connection(conn, event, commit)
            .await?;
    }
    let target = match crate::message_revision_current_states::locked_message_target(
        conn,
        &event.realm_id,
        message_id,
    )
    .await
    {
        Ok(target) => target,
        Err(PersistenceError::NotFound(_)) => {
            return Err(conflict(
                ConflictCode::DependencyMissing,
                "the reaction target Message is not materialized at this cut",
            ));
        }
        Err(error) => return Err(error),
    };
    if target.scope_ref != event.scope_ref {
        return Err(conflict(
            ConflictCode::FailedPrecondition,
            "the reaction target is outside the reaction's signed scope",
        ));
    }
    crate::scope_access::ensure_scope_member(
        conn,
        &event.realm_id,
        &event.scope_ref,
        &event.actor_id,
    )
    .await?;
    require_visible_target(conn, event, commit, &target.current_commit_id).await?;
    // The scope's MLS send gate is decided by the unit of work for every
    // accepted application carrier, reactions included, in this transaction.
    Ok(())
}

/// Resolve the current Message carrier only on the governing admission path.
/// The original add of an active reaction is never needed by a replica.
async fn require_visible_target(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    target_commit_id: &str,
) -> PersistenceResult<()> {
    #[derive(diesel::QueryableByName)]
    struct AcceptedTarget {
        #[diesel(sql_type = Jsonb)]
        envelope: Value,
        #[diesel(sql_type = Jsonb)]
        commit_json: Value,
    }
    let source = diesel::sql_query(
        "SELECT e.envelope,c.commit_json FROM realm_commits c \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE c.realm_id=$1 AND c.commit_id=$2 AND e.state='committed'",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(target_commit_id)
    .get_result::<AcceptedTarget>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| corrupt("Message current has no accepted carrier"))?;
    let full = arkret_wire::CommittedEventFullView {
        event: serde_json::from_value(source.envelope).map_err(corrupt)?,
        commit: serde_json::from_value(source.commit_json).map_err(corrupt)?,
    };
    let target_ref = event.payload.get("target_ref").and_then(Value::as_str);
    let exact_target = match full.event.kind {
        arkret_wire::EventKind::MessageCreate => {
            target_ref == Some(arkret_wire::MessageId::from_event_id(&full.event.event_id).as_str())
        }
        arkret_wire::EventKind::MessageRevise => {
            full.event.payload.get("message_id").and_then(Value::as_str) == target_ref
        }
        _ => false,
    };
    if !exact_target
        || full.event.realm_id != event.realm_id
        || full.event.scope_ref != event.scope_ref
        || full.commit.event_ref != full.event.event_id
        || full.commit.stream_ref != commit.stream_ref
        || full.commit.stream_position >= commit.stream_position
    {
        return Err(corrupt(
            "Message current does not bind this target's preceding source",
        ));
    }
    let floor = match &event.scope_ref {
        arkret_wire::ScopeRef::Realm { .. } => {
            crate::account_stream_scan::caller_realm_floor_in_connection(
                conn,
                &event.realm_id,
                &event.actor_id,
            )
            .await?
        }
        arkret_wire::ScopeRef::Circle { circle_id, .. } => {
            crate::account_stream_scan::caller_circle_floor_in_connection(
                conn,
                &event.realm_id,
                circle_id,
                &event.actor_id,
            )
            .await?
        }
        _ => None,
    };
    let withheld = crate::committed_disclosure::withheld_commit_ids_in_connection(
        conn,
        &[target_commit_id.to_owned()],
    )
    .await?;
    if floor.is_none_or(|floor| full.commit.stream_position < floor.oldest_position)
        || !withheld.is_empty()
        || !crate::committed_disclosure::full_event_for_member_in_connection(
            conn,
            &full,
            &event.actor_id,
            commit.committed_at,
        )
        .await?
    {
        return Err(PersistenceError::NotFound(
            "reaction target not found".to_owned(),
        ));
    }
    Ok(())
}

/// Derive one complete active value from the frozen current and an accepted
/// source. Native producer verification belongs to the enclosing transaction.
pub(crate) async fn commit_reaction_current_state_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    authorize: bool,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if !matches!(
        event.kind,
        arkret_wire::EventKind::ReactionAdd | arkret_wire::EventKind::ReactionRemove
    ) {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let stream =
        arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if commit.realm_id != event.realm_id
        || commit.stream_ref != stream
        || commit.event_ref != event.event_id
    {
        return Err(conflict(
            ConflictCode::FailedPrecondition,
            "reaction differs from its accepting source stream",
        ));
    }
    let (payload, message_id) = reaction_payload(event)?;
    if authorize {
        admit_reaction_in_connection(conn, event, commit, &message_id, prepared).await?;
    } else {
        // Without a complete baseline, an absent key is unknown rather than
        // inactive. The authority replica path holds the stream lock and
        // installs this head and the resulting current atomically.
        let head = crate::replica_authorization::verified_head(conn, &stream)
            .await?
            .ok_or_else(|| {
                conflict(
                    ConflictCode::DependencyMissing,
                    "reaction current baseline is not installed",
                )
            })?;
        if head.stream_position.checked_add(1) != Some(commit.stream_position)
            || commit.previous_commit_ref.as_ref() != Some(&head.commit_id)
        {
            return Err(conflict(
                ConflictCode::FailedPrecondition,
                "reaction current tail is not the next installed Commit",
            ));
        }
    }
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| corrupt("reaction stream position exceeds BIGINT"))?;
    let current = diesel::sql_query(
        "SELECT value,current_stream_position,current_commit_id,source_stream_ref \
         FROM message_reactions_current_states \
         WHERE realm_id=$1 AND target_ref=$2 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(message_id.as_str())
    .get_result::<ReactionSetRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let set = match current {
        Some(row) => {
            if row.source_stream_ref != serde_json::to_value(&stream).map_err(corrupt)?
                || row.current_stream_position >= position
            {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "reaction current is not on this Commit's stream prefix",
                ));
            }
            let set: MessageReactionsCurrentValue =
                serde_json::from_value(row.value).map_err(corrupt)?;
            let revision = arkret_wire::CurrentRevision {
                commit_id: row.current_commit_id.parse().map_err(corrupt)?,
                stream_position: u64::try_from(row.current_stream_position).map_err(corrupt)?,
            };
            set.validate_installation(
                message_id.as_str(),
                &stream,
                &revision,
                &arkret_wire::CommitStreamHead {
                    stream_ref: stream.clone(),
                    commit_id: commit.commit_id.clone(),
                    stream_position: commit.stream_position,
                },
                None,
            )
            .map_err(corrupt)?;
            set
        }
        None => {
            if !authorize {
                // A Snapshot may omit an invisible old target. A later
                // visible revision does not prove its former reaction set
                // empty. Only a disclosed target baseline or a creation in
                // the continuous post-Snapshot tail supplies that proof.
                #[derive(diesel::QueryableByName)]
                struct KnownEmptyBaseline {
                    #[diesel(sql_type = diesel::sql_types::Bool)]
                    present: bool,
                }
                let target_selector = arkret_wire::CurrentSelector::MessageRevision {
                    message_id: message_id.clone(),
                };
                let target_event = message_id.event_id();
                let token = crate::ids::parse_event_id(target_event.as_str())
                    .ok_or_else(|| corrupt("reaction target Event token is invalid"))?;
                let known = diesel::sql_query(
                    "SELECT (EXISTS(SELECT 1 FROM replica_authorization_rows r \
                       WHERE r.realm_id=$1 AND r.source_stream_ref=$2 AND r.selector=$3) \
                     OR EXISTS(SELECT 1 FROM canonical_events e \
                       JOIN realm_commits c ON c.event_pk=e.pk \
                       JOIN replica_authorization_cuts a ON a.realm_id=c.realm_id AND a.source_stream_ref=c.stream_ref \
                       WHERE e.id=$4 AND e.realm_id=$1 AND e.kind='ak.message.create' AND e.state='committed' \
                         AND c.realm_id=$1 AND c.stream_ref=$2 \
                         AND c.stream_position>a.circle_effect_base_stream_position \
                         AND c.stream_position<=a.head_stream_position)) AS present",
                )
                .bind::<Text, _>(event.realm_id.as_str())
                .bind::<Jsonb, _>(serde_json::to_value(&stream).map_err(corrupt)?)
                .bind::<Jsonb, _>(serde_json::to_value(target_selector).map_err(corrupt)?)
                .bind::<diesel::sql_types::Binary, _>(token.to_vec())
                .get_result::<KnownEmptyBaseline>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
                if !known.present {
                    return Err(conflict(
                        ConflictCode::DependencyMissing,
                        "reaction target needs a complete visible current Snapshot baseline",
                    ));
                }
            }
            MessageReactionsCurrentValue::new(Vec::new()).map_err(corrupt)?
        }
    };
    let mut entries = set.into_entries();
    entries.retain(|entry| entry.actor_id != event.actor_id || entry.key != payload.key);
    if event.kind == arkret_wire::EventKind::ReactionAdd {
        entries.push(ReactionCurrentEntry {
            actor_id: event.actor_id.clone(),
            key: payload.key,
            source: arkret_wire::CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: commit.commit_id.clone(),
                stream_ref: stream.clone(),
                stream_position: commit.stream_position,
            },
        });
    }
    let mut ordered = entries
        .into_iter()
        .map(|entry| {
            Ok((
                arkret_canonical::canonical_json_bytes(&entry.actor_id).map_err(corrupt)?,
                entry,
            ))
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    ordered.sort_by(|(left_actor, left), (right_actor, right)| {
        left_actor
            .cmp(right_actor)
            .then(left.key.as_bytes().cmp(right.key.as_bytes()))
    });
    let set =
        MessageReactionsCurrentValue::new(ordered.into_iter().map(|(_, entry)| entry).collect())
            .map_err(corrupt)?;
    let value = serde_json::to_value(&set).map_err(PersistenceError::database)?;
    diesel::sql_query(
        "INSERT INTO message_reactions_current_states \
         (realm_id,target_ref,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7) \
         ON CONFLICT (realm_id,target_ref) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value, updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(message_id.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(&stream).map_err(corrupt)?)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !authorize {
        let entry = arkret_wire::CurrentState::Value {
            selector: arkret_wire::CurrentSelector::MessageReactions {
                target_ref: message_id.to_string(),
            },
            source_stream_ref: stream,
            revision: arkret_wire::CurrentRevision {
                commit_id: commit.commit_id.clone(),
                stream_position: commit.stream_position,
            },
            value,
        };
        crate::replica_authorization::save_effect_row(
            conn,
            &event.realm_id,
            &entry,
            commit.committed_at,
        )
        .await?;
    }
    Ok(())
}
