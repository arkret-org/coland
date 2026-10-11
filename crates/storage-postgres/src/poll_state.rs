//! Plaintext PollState inputs derived from canonical Events and their accepting Commits.
//! The durable index stores references only; selections, Actors and scopes remain
//! canonical Event facts. Its SQL view recomputes winners by stream position.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::events_payloads::message::PollResponseHead;
use arkret_models_collaboration::events_payloads::poll::PollContentBlock;
use arkret_models_collaboration::poll::{PollPartition, VerifiedPollResponse};
use arkret_wire::{CommittedEventRef, Event, EventId, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::OptionalExtension;
use diesel::sql_types::{BigInt, Binary, Jsonb, Text};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

fn refusal(reason: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: Poll admission: {reason}"))
}

pub(crate) fn supported_plaintext_poll(payload: &Value) -> Option<PollContentBlock> {
    let object = payload.as_object()?;
    if !object.keys().all(|key| {
        matches!(
            key.as_str(),
            "strand_id" | "track_name" | "content" | "poll_response_heads" | "reply_to_id"
        )
    }) || !object.contains_key("strand_id")
        || object.get("track_name")? != "discussion"
    {
        return None;
    }
    let poll: PollContentBlock = serde_json::from_value(object.get("content")?.clone()).ok()?;
    poll.validate().ok()?;
    if matches!(poll, PollContentBlock::Definition(_)) && object.contains_key("poll_response_heads")
    {
        return None;
    }
    Some(poll)
}

#[derive(diesel::QueryableByName)]
struct AcceptedRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Text)]
    commit_id: String,
    #[diesel(sql_type = Jsonb)]
    stream_ref: Value,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
}

impl AcceptedRow {
    fn facts(&self) -> PersistenceResult<(Event, CommittedEventRef)> {
        let event: Event =
            serde_json::from_value(self.envelope.clone()).map_err(PersistenceError::database)?;
        let reference = CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: arkret_wire::RealmCommitId::new(self.commit_id.clone())
                .map_err(PersistenceError::database)?,
            stream_ref: serde_json::from_value(self.stream_ref.clone())
                .map_err(PersistenceError::database)?,
            stream_position: u64::try_from(self.stream_position)
                .map_err(PersistenceError::database)?,
        };
        Ok((event, reference))
    }
}

async fn accepted_event(
    conn: &mut AsyncPgConnection,
    id: &EventId,
    require_response: bool,
) -> PersistenceResult<AcceptedRow> {
    let token = crate::ids::parse_event_id(id.as_str())
        .ok_or_else(|| refusal("invalid target identity"))?;
    diesel::sql_query(
        "SELECT e.pk,e.envelope,c.commit_id,c.stream_ref,c.stream_position \
         FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.kind='ak.message.create' AND e.state='committed' \
           AND ($2=false OR EXISTS (SELECT 1 FROM poll_response_inputs p WHERE p.response_event_pk=e.pk AND p.commit_id=c.commit_id))",
    ).bind::<Binary,_>(token.to_vec())
        .bind::<diesel::sql_types::Bool,_>(require_response)
        .get_result::<AcceptedRow>(conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| refusal("target is not an accepted poll input"))
}

/// Returns true only for a response, whose MessageState materialization is forbidden.
pub(crate) async fn admit_poll_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    content: PollContentBlock,
    heads: &[PollResponseHead],
) -> PersistenceResult<bool> {
    let PollContentBlock::Response(response) = content else {
        return Ok(false);
    };
    let original = accepted_event(conn, &response.poll_response.poll_ref.event_id(), false).await?;
    let (poll_event, poll_commit) = original.facts()?;
    if poll_event.realm_id != event.realm_id
        || poll_event.scope_ref != event.scope_ref
        || poll_commit.stream_ref != commit.stream_ref
        || poll_commit.stream_position >= commit.stream_position
    {
        return Err(refusal(
            "poll is outside the response's accepted source scope",
        ));
    }
    let payload = serde_json::to_value(&poll_event.payload).map_err(PersistenceError::database)?;
    let Some(PollContentBlock::Definition(definition)) = supported_plaintext_poll(&payload) else {
        return Err(refusal(
            "target does not contain an admitted plaintext PollBlock",
        ));
    };
    let partition = PollPartition {
        realm_id: event.realm_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        poll_ref: response.poll_response.poll_ref.clone(),
        poll_event_ref: poll_event.event_id.clone(),
        actor_id: event.actor_id.clone(),
    };
    let mut predecessors = BTreeMap::new();
    for head in heads {
        let prior = accepted_event(conn, &head.response_event_ref, true).await?;
        let (prior_event, prior_ref) = prior.facts()?;
        let prior_payload =
            serde_json::to_value(&prior_event.payload).map_err(PersistenceError::database)?;
        let Some(PollContentBlock::Response(prior_response)) =
            supported_plaintext_poll(&prior_payload)
        else {
            return Err(refusal("head does not contain an admitted poll response"));
        };
        if prior_event.scope_ref != event.scope_ref {
            return Err(refusal("head source scope differs"));
        }
        predecessors.insert(
            prior_event.event_id,
            (
                PollPartition {
                    realm_id: prior_event.realm_id,
                    stream_ref: prior_ref.stream_ref.clone(),
                    poll_event_ref: prior_response.poll_response.poll_ref.event_id(),
                    poll_ref: prior_response.poll_response.poll_ref,
                    actor_id: prior_event.actor_id,
                },
                prior_ref,
            ),
        );
    }
    let answers = definition
        .poll
        .answers
        .iter()
        .map(|answer| answer.id.clone())
        .collect::<BTreeSet<_>>();
    VerifiedPollResponse::new(
        partition,
        CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: commit.commit_id.clone(),
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
        },
        &response.poll_response.selections,
        &answers,
        usize::try_from(definition.poll.max_selections).map_err(PersistenceError::database)?,
        heads.to_vec(),
        |id| predecessors.get(id).cloned(),
    )
    .map_err(|error| refusal(&error.to_string()))?;
    let inserted = diesel::sql_query(
        "INSERT INTO poll_response_inputs (response_event_pk,poll_event_pk,commit_id) \
         SELECT e.pk,$1,$2 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE c.commit_id=$2 AND e.envelope->>'event_id'=$3 AND e.state='committed'",
    )
    .bind::<BigInt, _>(original.pk)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(refusal("response has no matching accepting Commit"));
    }
    Ok(true)
}
