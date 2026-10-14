//! The `message_reactions` typed current writer at the accepting RealmCommit
//! cut.
//!
//! `models/strand-and-message.md` section 9.8.3: `ak.reaction.add` and
//! `ak.reaction.remove` each project exactly one `keyed_set_add` into the
//! per-target set. Every element is tagged by the accepting Event's
//! `<event_id>:0` dot and carries the complete payload; a remove is itself an
//! asserted element, so no writer ever deletes one. The asserting actor and
//! the polarity are read from the signed envelope the dot names. Remove-wins
//! membership, deduplication and counts are read-side folds.
//!
//! Admission (section 9.8.2 / 9.8.4): the actor holds `ak.reaction.add` or
//! `ak.reaction.remove` at the same cut, the target is an accepted
//! `ak:message:` of this Realm signed in the exact scope of the reaction, and
//! the scope's MLS send gate (`mls_group_current_results`) admits the carrier.
//! A target this Station has not materialized is `dependency_missing` with
//! zero writes.

use arkret_models_collaboration::events_payloads::reaction::{
    MessageReactionsCurrentValue, ReactionAssertionEntry, ReactionPayload,
};
use arkret_models_collaboration::exact_current_results::CanonicalEventDot;
use coland_storage::{ConflictCode, PersistenceError, PersistenceResult};
use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

#[derive(diesel::QueryableByName)]
struct ReactionSetRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Jsonb)]
    stream_ref: Value,
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
        crate::circle_current_results::require_active_author_in_connection(conn, event, commit)
            .await?;
    }
    let target = match crate::message_revision_current_results::locked_message_target(
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
    // The scope's MLS send gate is decided by the unit of work for every
    // accepted application carrier, reactions included, in this transaction.
    Ok(())
}

/// Add the reaction Event's single asserted element to its target's set.
/// `authorize` is the governing Station's admission; a verified replica fold
/// passes `false` and replays only the keyed-set join.
pub(crate) async fn commit_reaction_current_result_in_connection(
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
    if commit.stream_ref != stream || commit.event_ref != event.event_id {
        return Err(conflict(
            ConflictCode::FailedPrecondition,
            "reaction differs from its accepting source stream",
        ));
    }
    let (payload, message_id) = reaction_payload(event)?;
    if authorize {
        admit_reaction_in_connection(conn, event, commit, &message_id, prepared).await?;
    }
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| corrupt("reaction stream position exceeds BIGINT"))?;
    let current = diesel::sql_query(
        "SELECT s.value, s.current_stream_position, c.stream_ref \
         FROM message_reactions_current_results s \
         JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id \
         WHERE s.realm_id=$1 AND s.target_ref=$2 FOR UPDATE OF s",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(message_id.as_str())
    .get_result::<ReactionSetRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let set = match current {
        Some(row) => {
            // Every assertion of one target stays in one authority stream
            // (section 9.8.3), advanced strictly in Commit order.
            if row.stream_ref != serde_json::to_value(&stream).map_err(corrupt)?
                || row.current_stream_position >= position
            {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "reaction set is not on this Commit's stream prefix",
                ));
            }
            let set: MessageReactionsCurrentValue =
                serde_json::from_value(row.value).map_err(corrupt)?;
            set.validate_for_target(message_id.as_str())
                .map_err(corrupt)?;
            set
        }
        None => MessageReactionsCurrentValue::new(Vec::new()).map_err(corrupt)?,
    };
    let tag_id = CanonicalEventDot::new(event.event_id.clone(), 0).map_err(corrupt)?;
    if set.assertions().iter().any(|entry| entry.tag_id == tag_id) {
        return Err(conflict(
            ConflictCode::DuplicateConflict,
            "reaction assertion already exists",
        ));
    }
    let set = set
        .with_assertion(ReactionAssertionEntry {
            tag_id,
            value: payload,
        })
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let value = serde_json::to_value(&set).map_err(PersistenceError::database)?;
    diesel::sql_query(
        "INSERT INTO message_reactions_current_results \
         (realm_id,target_ref,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) \
         ON CONFLICT (realm_id,target_ref) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value, updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(message_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}
