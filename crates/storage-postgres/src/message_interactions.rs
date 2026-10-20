//! Message references admitted against exact accepted facts at the write cut.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::events_payloads::message::{
    ContentBlockKind, MessageCreatePayload,
};
use arkret_models_collaboration::events_payloads::poll::PollContentBlock;
use arkret_models_collaboration::poll::{PollPartition, VerifiedPollResponse};
use arkret_wire::{CommittedEventRef, Event, EventId, EventKind, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::OptionalExtension as _;
use diesel::sql_types::{Binary, Jsonb, Text};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

#[derive(diesel::QueryableByName)]
struct AcceptedRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

/// Authors retain their full Account; Agent execution retains its current owner.
/// Profile classification is optional display data, never authorization proof.
/// The ingress producer guard independently authenticates and classifies the
/// principal; closed Applet authoring retains its dedicated accepted-fact cut.

pub(crate) async fn require_message_actor(
    conn: &mut AsyncPgConnection,
    event: &Event,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if event.applet_id.is_some() {
        return crate::managed_message_actor::require_managed_actor_in_connection(conn, event, at)
            .await;
    }
    if event.payload.contains_key("agent_context") {
        return Err(rejected("Agent attribution belongs to the Event envelope"));
    }
    if event.executed_by.is_some() {
        let controller = crate::realm_authorization_cut::owned_controller_in_connection(
            conn,
            &event.realm_id,
            event.actual_signer(),
            at,
        )
        .await?;
        if controller.as_ref() != Some(&event.actor_id) {
            return Err(rejected(
                "Message executor lacks its exact current controller source",
            ));
        }
        let reference = event
            .authorization_ref
            .as_ref()
            .ok_or_else(|| rejected("attributed Message lacks authorization_ref"))?;
        arkret_wire::GrantId::new(reference.as_str())
            .map_err(|_| rejected("attributed Message must select its actual capability grant"))?;
    }
    event
        .actor_id
        .as_account_id()
        .ok_or_else(|| rejected("Message actor is not a full Account"))?;
    Ok(())
}

fn rejected(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}

fn accepted_ref(commit: &RealmCommit) -> CommittedEventRef {
    CommittedEventRef {
        event_id: commit.event_ref.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    }
}

async fn require_reference_visibility(
    conn: &mut AsyncPgConnection,
    event: &Event,
    referenced: &RealmCommit,
) -> PersistenceResult<()> {
    let floor = match &event.scope_ref {
        arkret_wire::ScopeRef::Realm { .. } => {
            crate::account_stream_scan::caller_realm_floor_in_connection(
                conn,
                &event.realm_id,
                &event.actor_id,
            )
            .await?
            .map(|floor| floor.oldest_position)
        }
        arkret_wire::ScopeRef::Circle { circle_id, .. } => {
            crate::account_stream_scan::caller_circle_floor_in_connection(
                conn,
                &event.realm_id,
                circle_id,
                &event.actor_id,
            )
            .await?
            .map(|floor| floor.oldest_position)
        }
        arkret_wire::ScopeRef::Sidecar { sidecar_id, .. } => {
            crate::sidecar_authority_cut::caller_floor_in_connection(
                conn,
                &event.realm_id,
                sidecar_id,
                &event.actor_id,
            )
            .await?
            .map(|floor| floor.oldest_position)
        }
        _ => None,
    }
    .ok_or_else(|| rejected("Message reference visibility has no proved membership floor"))?;
    if referenced.stream_position < floor {
        return Err(rejected(
            "Message reference precedes this actor's readable floor",
        ));
    }
    Ok(())
}

pub(crate) async fn require_reply_and_mentions_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    payload: &MessageCreatePayload,
) -> PersistenceResult<()> {
    if let Some(reply) = &payload.reply_to_id {
        let target = arkret_wire::MessageId::new(reply)
            .map_err(|_| rejected("Reply target is not a Message id"))?;
        let (_, target_commit, _) =
            accepted_message(conn, event, &target.event_id(), commit).await?;
        if crate::message_revision_current_results::message_is_redacted(
            conn,
            &event.realm_id,
            &target,
        )
        .await?
        {
            return Err(rejected("Reply target is not available in this discussion"));
        }
        require_reference_visibility(conn, event, &target_commit).await?;
    }
    if let Some(content) = &payload.content {
        if content.extra.contains_key("audience_mentions") {
            return Err(rejected(
                "Audience mentions require the broadcast admission cut",
            ));
        }
        if let Some(raw) = content.extra.get("mentions") {
            let mentions: Vec<arkret_models_collaboration::events_payloads::mention::Mention> =
                serde_json::from_value(raw.clone())
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            for mention in mentions {
                let actor = arkret_wire::ActorId::account(mention.subject_account_id);
                crate::moderation_report_current_results::ensure_scope_member(
                    conn,
                    &event.realm_id,
                    &event.scope_ref,
                    &actor,
                )
                .await?;
            }
        }
    }
    Ok(())
}

/// Event ids are indexed immutable accepted facts; a missing or queued fact
/// cannot stand in for a poll definition or a replacement declaration.
async fn accepted_message(
    conn: &mut AsyncPgConnection,
    event: &Event,
    event_id: &EventId,
    current: &RealmCommit,
) -> PersistenceResult<(Event, RealmCommit, MessageCreatePayload)> {
    let token = crate::ids::parse_event_id(event_id.as_str())
        .ok_or_else(|| rejected("Message reference is invalid"))?;
    let row = diesel::sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.realm_id=$2 AND e.state='committed' \
           AND e.kind='ak.message.create'",
    )
    .bind::<Binary, _>(token.to_vec())
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<AcceptedRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| rejected("Message reference has no accepted creating Event"))?;
    let referenced: Event =
        serde_json::from_value(row.envelope).map_err(PersistenceError::database)?;
    let commit: RealmCommit =
        serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
    if referenced.event_id != *event_id
        || referenced.scope_ref != event.scope_ref
        || commit.event_ref != referenced.event_id
        || commit.stream_ref != current.stream_ref
        || commit.stream_position >= current.stream_position
    {
        return Err(rejected(
            "Message reference differs from its effective stream",
        ));
    }
    let payload = serde_json::from_value(
        serde_json::to_value(&referenced.payload).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    Ok((referenced, commit, payload))
}

pub(crate) async fn require_poll_content_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    payload: &MessageCreatePayload,
) -> PersistenceResult<()> {
    if event.kind != EventKind::MessageCreate {
        return Ok(());
    }
    let block = payload.content.as_ref();
    let is_poll = block.is_some_and(|content| {
        matches!(
            content.kind,
            ContentBlockKind::Poll | ContentBlockKind::PollResponse
        )
    });
    if !is_poll {
        if !payload.poll_response_heads.is_empty() {
            return Err(rejected(
                "Replacement declarations require poll response content",
            ));
        }
        return Ok(());
    }
    let block: PollContentBlock = serde_json::from_value(
        serde_json::to_value(block.unwrap()).map_err(PersistenceError::database)?,
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    block
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let PollContentBlock::Response(response) = block else {
        if !payload.poll_response_heads.is_empty() {
            return Err(rejected("A poll definition cannot declare response heads"));
        }
        return Ok(());
    };
    let poll_id = response.poll_response.poll_ref.event_id();
    let (definition_event, definition_commit, definition_payload) =
        accepted_message(conn, event, &poll_id, commit).await?;
    require_reference_visibility(conn, event, &definition_commit).await?;
    if crate::message_revision_current_results::message_is_redacted(
        conn,
        &event.realm_id,
        &response.poll_response.poll_ref,
    )
    .await?
    {
        return Err(rejected("Poll target is not available in this discussion"));
    }
    let definition: PollContentBlock = serde_json::from_value(
        serde_json::to_value(definition_payload.content).map_err(PersistenceError::database)?,
    )
    .map_err(|_| rejected("Poll target is not a poll definition"))?;
    let PollContentBlock::Definition(definition) = definition else {
        return Err(rejected("Poll target is not a poll definition"));
    };
    let partition = PollPartition {
        realm_id: event.realm_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        poll_ref: response.poll_response.poll_ref.clone(),
        poll_event_ref: definition_event.event_id,
        actor_id: event.actor_id.clone(),
    };
    let mut heads = BTreeMap::new();
    for head in &payload.poll_response_heads {
        let (prior, prior_commit, prior_payload) =
            accepted_message(conn, event, &head.response_event_ref, commit).await?;
        let prior_content: PollContentBlock = serde_json::from_value(
            serde_json::to_value(prior_payload.content).map_err(PersistenceError::database)?,
        )
        .map_err(|_| rejected("Poll head is not an accepted response"))?;
        let PollContentBlock::Response(prior_content) = prior_content else {
            return Err(rejected("Poll head is not an accepted response"));
        };
        if prior.actor_id != event.actor_id
            || prior_content.poll_response.poll_ref != partition.poll_ref
        {
            return Err(rejected("Poll head belongs to another response partition"));
        }
        heads.insert(
            prior.event_id,
            (partition.clone(), accepted_ref(&prior_commit)),
        );
    }
    let answers = definition
        .poll
        .answers
        .into_iter()
        .map(|answer| answer.id)
        .collect::<BTreeSet<_>>();
    VerifiedPollResponse::new(
        partition,
        accepted_ref(commit),
        &response.poll_response.selections,
        &answers,
        usize::try_from(definition.poll.max_selections)
            .map_err(|_| rejected("Poll selection maximum is invalid"))?,
        payload.poll_response_heads.clone(),
        |id| heads.get(id).cloned(),
    )
    .map_err(rejected)?;
    Ok(())
}
