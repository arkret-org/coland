//! The `object_redaction` typed current writer of `ak.message.redact` at the
//! accepting RealmCommit cut.
//!
//! `models/event-and-patch.md` §4.2.4 and `sync/current-state.md` make every
//! committed redaction one assertion in the set of its verbatim target: the
//! element is tagged by the accepting Event's `<event_id>:0` dot and carries
//! the complete redact payload, and no writer removes an element. A Message
//! that is already redacted is terminal, so a second redact of it is refused
//! and its subject holds exactly one assertion. The Message's own state is
//! never mirrored here; every read path derives the withheld Message from
//! this family.
//!
//! Authorization is the same-cut evaluator of
//! [`crate::realm_authorization_cut`]: a joined member holding
//! `ak.message.redact`, or the author holding `ak.message.redact.own` inside
//! its redact window. `ak.redaction` (other objects and Event targets) has no
//! authority cut here and stays closed at its caller.

use arkret_models_collaboration::events_payloads::message::MessageRedactPayload;
use arkret_models_collaboration::events_payloads::redaction::{
    ObjectRedactionAssertionValue, ObjectRedactionCurrentValue, ObjectRedactionEntry,
};
use arkret_models_collaboration::exact_current_state::CanonicalEventDot;
use coland_storage::{ConflictCode, PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::RunQueryDsl;

use crate::message_revision_current_states::{
    locked_message_target, message_is_redacted, require_active_discussion_strand,
    require_message_write_carrier,
};
use crate::realm_authorization_cut::{
    AuthoredTarget, RealmAuthorizationCut, lock_realm_authorization_cut,
};

fn schema_violation(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_string())
}

/// The `object_redaction` value a first `ak.message.redact` of a Message
/// establishes: its one assertion, tagged by the Event's `<event_id>:0` dot.
pub(crate) fn message_redaction_current_value(
    event: &arkret_wire::Event,
    payload: MessageRedactPayload,
) -> PersistenceResult<ObjectRedactionCurrentValue> {
    Ok(ObjectRedactionCurrentValue {
        assertions: vec![ObjectRedactionEntry {
            tag_id: CanonicalEventDot::new(event.event_id.clone(), 0).map_err(schema_violation)?,
            value: ObjectRedactionAssertionValue::Message(payload),
        }],
    })
}

/// Admit `ak.message.redact` and add its assertion to the Message's
/// `object_redaction` set. Every other kind is left to its own writer.
pub(crate) async fn commit_message_redact_current_state_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::MessageRedact {
        return Ok(());
    }
    require_message_write_carrier(event, commit)?;
    let payload: MessageRedactPayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(schema_violation)?;
    lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let cut = RealmAuthorizationCut::read_for_event(conn, event).await?;
    cut.require_governed_member(&event.kind)?;
    let target = locked_message_target(conn, &event.realm_id, &payload.message_id).await?;
    if target.scope_ref != event.scope_ref {
        return Err(PersistenceError::NotFound("message not found".to_owned()));
    }
    crate::moderation_report_current_states::ensure_scope_member(
        conn,
        &event.realm_id,
        &event.scope_ref,
        &event.actor_id,
    )
    .await?;
    cut.require_authored_target_in_connection(
        conn,
        event,
        &AuthoredTarget {
            author: &target.author,
            created_at: target.created_at,
            strand_id: &target.strand_id,
        },
        commit,
        prepared,
    )
    .await?;
    if message_is_redacted(conn, &event.realm_id, &target.message_id).await? {
        return Err(PersistenceError::Conflict(format!(
            "{}: the Message is already redacted",
            ConflictCode::FailedPrecondition
        )));
    }
    // `strand-and-message.md` §4: a Message of a Strand whose discussion
    // track is not active is refused for redact as for create and revise.
    require_active_discussion_strand(conn, &event.realm_id, &target.strand_id, &event.scope_ref)
        .await?;
    let value = message_redaction_current_value(event, payload)?;
    value
        .validate_for_subject(target.message_id.as_str())
        .map_err(schema_violation)?;
    let inserted = diesel::sql_query(
        "INSERT INTO object_redaction_current_states \
         (realm_id,target_ref,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(target.message_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(
        i64::try_from(commit.stream_position)
            .map_err(|_| schema_violation("redaction stream position exceeds BIGINT"))?,
    )
    .bind::<Jsonb, _>(&serde_json::to_value(&value).map_err(PersistenceError::database)?)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(PersistenceError::Internal(
            "object_redaction row appeared inside the Message lock".to_owned(),
        ));
    }
    Ok(())
}
