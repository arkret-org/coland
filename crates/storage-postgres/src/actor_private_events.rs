//! `ak.self.actor_private_events.command.submit.v1` over PostgreSQL
//! (actor-private-effects.md §2.1, §3.2, §3.3).
//!
//! One transaction serializes the Event identity and the effect's unique key,
//! answers an exact retry from the actor-private ledger, rechecks the producer
//! guard, decides the branch's `concurrency` precondition and then writes the
//! value projection together with the ledger row and its first outcome. Every
//! refusal is decided before the first write, so it writes nothing. No
//! RealmCommit is produced or read.

use arkret_models_identity::device_push_route::{
    DevicePushRoutePayload, ServerRevisionCasDecision, decide_server_revision_cas,
};
use arkret_wire::ActorPrivateEventSubmitOutcome;
use coland_storage::{
    ActorPrivateEventEffect, ActorPrivateEventRefusal, ActorPrivateEventStore,
    ActorPrivateEventSubmission, ActorPrivateEventSubmitResult,
};

use crate::agent_draft_pending_intents::commit_agent_draft_pending_intent_in_connection;
use crate::{
    AsyncConnection, AsyncPgConnection, BigInt, Binary, Jsonb, OptionalExtension, PersistenceError,
    PersistenceResult, PgPool, PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz,
    async_trait, pg_conn, sql_query,
};

#[derive(Clone)]
pub struct PgActorPrivateEventStore {
    pub(crate) pool: PgPool,
}

impl PgActorPrivateEventStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(QueryableByName)]
struct LedgerRow {
    #[diesel(sql_type = Binary)]
    canonical_event_digest: Vec<u8>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    outcome: Option<serde_json::Value>,
}

#[derive(QueryableByName)]
struct RevisionRow {
    #[diesel(sql_type = BigInt)]
    revision: i64,
}

#[derive(QueryableByName)]
struct RequestStateRow {
    #[diesel(sql_type = Text)]
    workflow_state: String,
    #[diesel(sql_type = Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    #[expect(dead_code, reason = "only the row's presence is read")]
    present: i32,
}

fn internal(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(error.to_string())
}

async fn lock(conn: &mut AsyncPgConnection, key: String) -> Result<(), PgTransactionError> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(key)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Check that the decoded effect is exactly the submitted Event's kind and
/// that its owner is the one this submission names.
fn bind_effect(submission: &ActorPrivateEventSubmission) -> PersistenceResult<()> {
    use arkret_wire::EventKind;
    let owner = &submission.owner;
    let bound = match &submission.effect {
        ActorPrivateEventEffect::DevicePushRoute(payload) => {
            submission.event.kind == EventKind::DevicePushRoute
                && &payload.scope().account_id == owner
        }
        ActorPrivateEventEffect::AgentActionRequest(payload) => {
            submission.event.kind == EventKind::AgentActionRequest
                && &payload.controller_account_id == owner
        }
        ActorPrivateEventEffect::AgentActionReject {
            payload,
            request_id,
        } => {
            submission.event.kind == EventKind::AgentActionReject
                && submission.event.actor_id.as_account_id() == Some(owner)
                && payload.request_id == *request_id
        }
        ActorPrivateEventEffect::AgentDraftPropose(commit) => {
            submission.event.kind == EventKind::AgentDraftPropose
                && &commit.record.controller_account_id == owner
                && commit.record.accepted_event_id == submission.event.event_id
                && commit
                    .record
                    .canonical_event_digest
                    .as_str()
                    .strip_prefix("sha256:")
                    == Some(
                        submission
                            .canonical_event_digest
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                            .as_str(),
                    )
        }
    };
    if !bound || submission.canonical_event_digest.len() != 32 {
        return Err(PersistenceError::SchemaViolation(
            "actor-private submission effect is not bound to its Event and owner".to_owned(),
        ));
    }
    Ok(())
}

async fn submit_in_connection(
    conn: &mut AsyncPgConnection,
    submission: &ActorPrivateEventSubmission,
) -> Result<ActorPrivateEventSubmitResult, PgTransactionError> {
    let event = &submission.event;
    lock(conn, format!("actor-private-event:{}", event.event_id)).await?;
    if let Some(row) = sql_query(
        "SELECT canonical_event_digest, outcome FROM actor_private_events WHERE event_id=$1",
    )
    .bind::<Text, _>(event.event_id.as_str())
    .get_result::<LedgerRow>(&mut *conn)
    .await
    .optional()?
    {
        if row.canonical_event_digest != submission.canonical_event_digest {
            return Ok(ActorPrivateEventSubmitResult::Refused(
                ActorPrivateEventRefusal::DuplicateConflict(
                    "the actor-private Event identity carries other bytes",
                ),
            ));
        }
        let outcome = serde_json::from_value::<ActorPrivateEventSubmitOutcome>(
            row.outcome
                .ok_or_else(|| internal("accepted actor-private Event has no outcome"))?,
        )
        .map_err(internal)?;
        if outcome.event_kind() != event.kind {
            return Err(internal("stored actor-private outcome is of another kind").into());
        }
        return Ok(ActorPrivateEventSubmitResult::Replayed(outcome));
    }
    if let Some(guard) = &submission.producer_guard {
        crate::authority_commit::check_self_producer_guard_in_connection(
            conn,
            event,
            guard,
            submission.accepted_at,
        )
        .await?;
    }
    let owner_key = submission.owner.to_string();
    let decided = match &submission.effect {
        ActorPrivateEventEffect::DevicePushRoute(payload) => {
            push_route(conn, submission, &owner_key, payload).await?
        }
        ActorPrivateEventEffect::AgentActionRequest(payload) => {
            let key = format!(
                "agent-action-request:{owner_key}:{}:{}",
                payload.agent_id, payload.request_id
            );
            lock(conn, key).await?;
            let occupied = sql_query(
                "SELECT 1 AS present FROM agent_action_requests \
                 WHERE controller_account_key=$1 AND agent_id=$2 AND request_id=$3",
            )
            .bind::<Text, _>(&owner_key)
            .bind::<Text, _>(payload.agent_id.as_str())
            .bind::<Text, _>(&payload.request_id)
            .get_result::<PresentRow>(&mut *conn)
            .await
            .optional()?
            .is_some();
            if occupied {
                Err(ActorPrivateEventRefusal::DuplicateConflict(
                    "the action request key is occupied by another Event",
                ))
            } else if submission.accepted_at >= payload.expires_at {
                Err(ActorPrivateEventRefusal::FailedPrecondition(
                    "the action request is expired",
                ))
            } else {
                sql_query(
                    "INSERT INTO agent_action_requests \
                     (controller_account_key, agent_id, request_id, request, workflow_state, \
                      accepted_event_id, expires_at, rejection_id) \
                     VALUES ($1,$2,$3,$4,'requested',$5,$6,NULL)",
                )
                .bind::<Text, _>(&owner_key)
                .bind::<Text, _>(payload.agent_id.as_str())
                .bind::<Text, _>(&payload.request_id)
                .bind::<Jsonb, _>(serde_json::to_value(payload).map_err(internal)?)
                .bind::<Text, _>(event.event_id.as_str())
                .bind::<Timestamptz, _>(payload.expires_at)
                .execute(&mut *conn)
                .await?;
                Ok(ActorPrivateEventSubmitOutcome::AgentActionRequest {
                    accepted_event_id: event.event_id.clone(),
                })
            }
        }
        ActorPrivateEventEffect::AgentActionReject {
            payload,
            request_id,
        } => reject(conn, submission, &owner_key, payload, request_id).await?,
        ActorPrivateEventEffect::AgentDraftPropose(commit) => {
            let record = &commit.record;
            let key = format!(
                "agent-draft-pending-intent:{owner_key}:{}:{}",
                record.agent_id, record.draft_id
            );
            lock(conn, key).await?;
            let occupied = sql_query(
                "SELECT 1 AS present FROM agent_draft_pending_intents \
                 WHERE controller_account_key=$1 AND agent_id=$2 AND draft_id=$3",
            )
            .bind::<Text, _>(&owner_key)
            .bind::<Text, _>(record.agent_id.as_str())
            .bind::<Text, _>(&record.draft_id)
            .get_result::<PresentRow>(&mut *conn)
            .await
            .optional()?
            .is_some();
            if occupied {
                Err(ActorPrivateEventRefusal::DuplicateConflict(
                    "the Agent draft key is occupied by another proposal",
                ))
            } else if submission.accepted_at >= record.expires_at {
                Err(ActorPrivateEventRefusal::FailedPrecondition(
                    "the Agent draft proposal is expired",
                ))
            } else {
                commit_agent_draft_pending_intent_in_connection(conn, commit).await?;
                Ok(ActorPrivateEventSubmitOutcome::AgentDraftPropose {
                    accepted_event_id: event.event_id.clone(),
                })
            }
        }
    };
    let outcome = match decided {
        Ok(outcome) => outcome,
        Err(refusal) => return Ok(ActorPrivateEventSubmitResult::Refused(refusal)),
    };
    sql_query(
        "INSERT INTO actor_private_events \
         (id, event_id, actor_id, kind, canonical_event_digest, envelope, outcome, accepted_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind::<Binary, _>(event.event_id.token_bytes().to_vec())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(event.actor_id.to_string())
    .bind::<Text, _>(event.kind.as_str())
    .bind::<Binary, _>(&submission.canonical_event_digest)
    .bind::<Jsonb, _>(serde_json::to_value(event).map_err(internal)?)
    .bind::<Jsonb, _>(serde_json::to_value(&outcome).map_err(internal)?)
    .bind::<Timestamptz, _>(submission.accepted_at)
    .execute(&mut *conn)
    .await?;
    Ok(ActorPrivateEventSubmitResult::Accepted(outcome))
}

/// `server_revision_cas`: the route is replaced as a whole value only when
/// `expected_server_revision` equals the stored revision (0 when absent).
async fn push_route(
    conn: &mut AsyncPgConnection,
    submission: &ActorPrivateEventSubmission,
    owner_key: &str,
    payload: &DevicePushRoutePayload,
) -> Result<Result<ActorPrivateEventSubmitOutcome, ActorPrivateEventRefusal>, PgTransactionError> {
    let scope = payload.scope();
    lock(
        conn,
        format!(
            "device-push-route:{owner_key}:{}:{}",
            scope.device_id, scope.push_route
        ),
    )
    .await?;
    let current = sql_query(
        "SELECT revision FROM device_push_routes \
         WHERE account_key=$1 AND device_id=$2 AND push_route=$3 FOR UPDATE",
    )
    .bind::<Text, _>(owner_key)
    .bind::<Text, _>(scope.device_id.as_str())
    .bind::<Text, _>(&scope.push_route)
    .get_result::<RevisionRow>(&mut *conn)
    .await
    .optional()?
    .map(|row| u64::try_from(row.revision).map_err(internal))
    .transpose()?;
    let revision = match decide_server_revision_cas(current, payload.expected_server_revision()) {
        ServerRevisionCasDecision::Accepted { next_revision } => {
            match i64::try_from(next_revision) {
                Ok(revision) => revision,
                Err(_) => return Ok(Err(ActorPrivateEventRefusal::CasConflict)),
            }
        }
        ServerRevisionCasDecision::Conflict | ServerRevisionCasDecision::Overflow => {
            return Ok(Err(ActorPrivateEventRefusal::CasConflict));
        }
    };
    let revoked = matches!(payload, DevicePushRoutePayload::Revoked(_));
    sql_query(
        "INSERT INTO device_push_routes \
         (account_key, device_id, push_route, route_value, revoked, revision, accepted_event_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) \
         ON CONFLICT (account_key, device_id, push_route) DO UPDATE SET \
         route_value=EXCLUDED.route_value, revoked=EXCLUDED.revoked, \
         revision=EXCLUDED.revision, accepted_event_id=EXCLUDED.accepted_event_id",
    )
    .bind::<Text, _>(owner_key)
    .bind::<Text, _>(scope.device_id.as_str())
    .bind::<Text, _>(&scope.push_route)
    .bind::<Jsonb, _>(serde_json::to_value(payload).map_err(internal)?)
    .bind::<diesel::sql_types::Bool, _>(revoked)
    .bind::<BigInt, _>(revision)
    .bind::<Text, _>(submission.event.event_id.as_str())
    .execute(&mut *conn)
    .await?;
    Ok(Ok(ActorPrivateEventSubmitOutcome::DevicePushRoute {
        accepted_event_id: submission.event.event_id.clone(),
        revision: revision.unsigned_abs(),
    }))
}

/// `target_state_cas`: the rejection id is unused and the one named request
/// of the same controller and Agent is present, `requested` and unexpired.
async fn reject(
    conn: &mut AsyncPgConnection,
    submission: &ActorPrivateEventSubmission,
    owner_key: &str,
    payload: &arkret_models_collaboration::events_payloads::agent::AgentActionRejectPayload,
    request_id: &str,
) -> Result<Result<ActorPrivateEventSubmitOutcome, ActorPrivateEventRefusal>, PgTransactionError> {
    let agent_id = payload.agent_id.as_str();
    lock(
        conn,
        format!(
            "agent-action-rejection:{owner_key}:{agent_id}:{}",
            payload.rejection_id
        ),
    )
    .await?;
    lock(
        conn,
        format!("agent-action-request:{owner_key}:{agent_id}:{request_id}"),
    )
    .await?;
    let reused = sql_query(
        "SELECT 1 AS present FROM agent_action_rejections \
         WHERE controller_account_key=$1 AND agent_id=$2 AND rejection_id=$3",
    )
    .bind::<Text, _>(owner_key)
    .bind::<Text, _>(agent_id)
    .bind::<Text, _>(&payload.rejection_id)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .optional()?
    .is_some();
    if reused {
        return Ok(Err(ActorPrivateEventRefusal::DuplicateConflict(
            "the rejection id is already used by another Event",
        )));
    }
    let Some(target) = sql_query(
        "SELECT workflow_state, expires_at FROM agent_action_requests \
         WHERE controller_account_key=$1 AND agent_id=$2 AND request_id=$3 FOR UPDATE",
    )
    .bind::<Text, _>(owner_key)
    .bind::<Text, _>(agent_id)
    .bind::<Text, _>(request_id)
    .get_result::<RequestStateRow>(&mut *conn)
    .await
    .optional()?
    else {
        return Ok(Err(ActorPrivateEventRefusal::FailedPrecondition(
            "the rejection target is missing for this controller and Agent",
        )));
    };
    if target.workflow_state != "requested" {
        return Ok(Err(ActorPrivateEventRefusal::FailedPrecondition(
            "the rejection target is already terminal",
        )));
    }
    if submission.accepted_at >= target.expires_at {
        return Ok(Err(ActorPrivateEventRefusal::FailedPrecondition(
            "the rejection target is expired",
        )));
    }
    sql_query(
        "INSERT INTO agent_action_rejections \
         (controller_account_key, agent_id, rejection_id, rejection, request_id, accepted_event_id) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind::<Text, _>(owner_key)
    .bind::<Text, _>(agent_id)
    .bind::<Text, _>(&payload.rejection_id)
    .bind::<Jsonb, _>(serde_json::to_value(payload).map_err(internal)?)
    .bind::<Text, _>(request_id)
    .bind::<Text, _>(submission.event.event_id.as_str())
    .execute(&mut *conn)
    .await?;
    let transitioned = sql_query(
        "UPDATE agent_action_requests SET workflow_state='rejected', rejection_id=$4 \
         WHERE controller_account_key=$1 AND agent_id=$2 AND request_id=$3 \
           AND workflow_state='requested'",
    )
    .bind::<Text, _>(owner_key)
    .bind::<Text, _>(agent_id)
    .bind::<Text, _>(request_id)
    .bind::<Text, _>(&payload.rejection_id)
    .execute(&mut *conn)
    .await?;
    if transitioned != 1 {
        return Err(internal("the locked rejection target changed state").into());
    }
    Ok(Ok(ActorPrivateEventSubmitOutcome::AgentActionReject {
        accepted_event_id: submission.event.event_id.clone(),
    }))
}

#[async_trait]
impl ActorPrivateEventStore for PgActorPrivateEventStore {
    async fn submit(
        &self,
        submission: &ActorPrivateEventSubmission,
    ) -> PersistenceResult<ActorPrivateEventSubmitResult> {
        bind_effect(submission)?;
        let mut conn = pg_conn(&self.pool).await?;
        conn.transaction::<_, PgTransactionError, _>(async move |conn| {
            submit_in_connection(conn, submission).await
        })
        .await
        .map_err(PgTransactionError::into_persistence)
    }
}
