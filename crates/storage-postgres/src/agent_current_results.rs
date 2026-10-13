use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz};
use serde_json::{Value, json};

use super::{
    AsyncPgConnection, OptionalExtension, PersistenceError, PersistenceResult, QueryableByName,
    RunQueryDsl, sql_query,
};

#[derive(QueryableByName)]
struct CurrentValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(QueryableByName)]
struct CurrentResultRow {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Nullable<Jsonb>)]
    source_stream_ref: Option<Value>,
}

pub(crate) async fn read_agent_current_result(
    pool: &super::PgPool,
    realm_id: &arkret_wire::RealmId,
    selector: &arkret_wire::CurrentSelector,
) -> PersistenceResult<Option<arkret_wire::TypedCurrentRow>> {
    let (query, current_key) = match selector {
        arkret_wire::CurrentSelector::AgentInteraction { agent_account_id } => (
            "SELECT result.current_commit_id,result.current_stream_position,result.value,COALESCE(covering.stream_ref,replica.source_stream_ref) AS source_stream_ref FROM agent_interaction_current_results result LEFT JOIN realm_commits covering ON covering.commit_id=result.current_commit_id AND covering.stream_position=result.current_stream_position AND covering.realm_id=result.realm_id LEFT JOIN replica_authorization_rows replica ON replica.realm_id=result.realm_id AND replica.selector=jsonb_build_object('kind','agent_interaction','agent_account_id',result.agent_account_id) AND replica.current_commit_id=result.current_commit_id AND replica.current_stream_position=result.current_stream_position AND replica.value=result.value WHERE result.realm_id=$1 AND result.current_key=$2",
            arkret_wire::derive_agent_interaction_current_key(agent_account_id)
                .map_err(|error| invalid(error.to_string()))?,
        ),
        arkret_wire::CurrentSelector::AgentStatus { agent_id } => (
            "SELECT result.current_commit_id,result.current_stream_position,result.value,covering.stream_ref AS source_stream_ref \
             FROM agent_status_current_results result LEFT JOIN realm_commits covering \
               ON covering.commit_id=result.current_commit_id \
              AND covering.stream_position=result.current_stream_position \
              AND covering.realm_id=result.realm_id \
             WHERE result.realm_id=$1 AND result.agent_id=$2",
            agent_id.as_str().to_owned(),
        ),
        arkret_wire::CurrentSelector::AgentKey {
            agent_id,
            agent_key_id,
        } => (
            "SELECT result.current_commit_id,result.current_stream_position,result.value,covering.stream_ref AS source_stream_ref \
             FROM agent_key_current_results result LEFT JOIN realm_commits covering \
               ON covering.commit_id=result.current_commit_id \
              AND covering.stream_position=result.current_stream_position \
              AND covering.realm_id=result.realm_id \
             WHERE result.realm_id=$1 AND result.current_key=$2",
            arkret_wire::derive_agent_key_current_key(agent_id, agent_key_id)
                .map_err(|error| invalid(error.to_string()))?,
        ),
        _ => return Err(invalid("current_agent_result requires an Agent selector")),
    };
    let mut conn = super::pg_conn(pool).await?;
    let row = sql_query(query)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(&current_key)
        .get_result::<CurrentResultRow>(&mut conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
    row.map(|row| {
        Ok(arkret_wire::TypedCurrentRow::Value {
            selector: selector.clone(),
            source_stream_ref: serde_json::from_value(row.source_stream_ref.ok_or_else(|| {
                PersistenceError::Internal(
                    "stored Agent current result has no covering RealmCommit".to_owned(),
                )
            })?)
            .map_err(|error| {
                invalid(format!(
                    "stored Agent source stream ref is invalid: {error}"
                ))
            })?,
            revision: arkret_wire::CurrentRevision {
                commit_id: arkret_wire::RealmCommitId::new(row.current_commit_id)
                    .map_err(|error| invalid(error.to_string()))?,
                stream_position: u64::try_from(row.current_stream_position)
                    .map_err(|_| invalid("stored Agent current stream position is negative"))?,
            },
            value: row.value,
        })
    })
    .transpose()
}

fn invalid(message: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(message.into())
}

fn agent_key_id(value: &str) -> PersistenceResult<arkret_wire::AgentKeyId> {
    arkret_wire::AgentKeyId::new(value.to_owned()).map_err(|error| invalid(error.to_string()))
}

fn authorization_entries(value: Value) -> PersistenceResult<Vec<Value>> {
    let entries = value
        .get("authorizations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("stored Agent key current value is invalid"))?;
    Ok(entries.clone())
}

fn active_event_id(entry: &Value) -> Option<&str> {
    entry.get("value")?.get("verification_method")?.as_str()?;
    entry
        .get("tag_id")?
        .as_str()?
        .rsplit_once(':')
        .map(|(id, _)| id)
}

fn remove_authorization(entries: &mut Vec<Value>, event_id: &arkret_wire::EventId) -> bool {
    let before = entries.len();
    entries.retain(|entry| active_event_id(entry) != Some(event_id.as_str()));
    before != entries.len()
}

fn canonicalize_entries(entries: &mut [Value]) -> PersistenceResult<()> {
    let mut sorted = entries
        .iter()
        .map(|entry| {
            let dot = serde_json::from_value::<
                arkret_models_collaboration::exact_current_results::CanonicalEventDot,
            >(entry["tag_id"].clone())
            .map_err(|_| invalid("Agent key current contains an invalid Event dot"))?;
            Ok((dot, entry.clone()))
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(invalid("Agent key current contains duplicate Event dots"));
    }
    for (entry, (_, value)) in entries.iter_mut().zip(sorted) {
        *entry = value;
    }
    Ok(())
}

async fn load_key(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    current_key: &str,
) -> PersistenceResult<Vec<Value>> {
    let existing = sql_query(
        "SELECT value FROM agent_key_current_results WHERE realm_id=$1 AND current_key=$2 FOR UPDATE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(current_key)
    .get_result::<CurrentValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    existing.map_or_else(|| Ok(Vec::new()), |row| authorization_entries(row.value))
}

async fn write_key(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    agent_id: &arkret_wire::DidCoreId,
    key_id: &arkret_wire::AgentKeyId,
    mut entries: Vec<Value>,
) -> PersistenceResult<()> {
    canonicalize_entries(&mut entries)?;
    let current_key = arkret_wire::derive_agent_key_current_key(agent_id, key_id)
        .map_err(|error| invalid(error.to_string()))?;
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| invalid("Agent key stream position exceeds i64"))?;
    sql_query(
        "INSERT INTO agent_key_current_results \
         (realm_id,current_key,agent_id,agent_key_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (realm_id,current_key) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&current_key)
    .bind::<Text, _>(agent_id.as_str())
    .bind::<Text, _>(key_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(json!({"authorizations":entries}))
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

pub(crate) async fn project_agent_key_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::events_payloads::agent::{
        AgentKeyAuthorizePayload, AgentKeyRevokePayload,
    };
    match event.kind {
        arkret_wire::EventKind::AgentKeyAuthorize => {
            let payload: AgentKeyAuthorizePayload = serde_json::from_value(json!(event.payload))
                .map_err(|error| invalid(error.to_string()))?;
            lock_agent_producer_current(conn, &event.realm_id, &payload.agent_id).await?;
            let all = sql_query(
                "SELECT value FROM agent_key_current_results WHERE realm_id=$1 AND agent_id=$2 FOR UPDATE",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(payload.agent_id.as_str())
            .load::<CurrentValueRow>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            let active_count = all
                .into_iter()
                .map(|row| authorization_entries(row.value))
                .collect::<PersistenceResult<Vec<_>>>()?
                .into_iter()
                .flatten()
                .filter(|entry| active_event_id(entry).is_some())
                .count();
            if active_count != payload.supersedes.len() {
                return Err(invalid(
                    "Agent key supersedes must name the complete active authorization set",
                ));
            }
            for prior in &payload.supersedes {
                let key_id = agent_key_id(prior.key_id.as_str())?;
                let key = arkret_wire::derive_agent_key_current_key(&payload.agent_id, &key_id)
                    .map_err(|error| invalid(error.to_string()))?;
                let mut entries = load_key(conn, &event.realm_id, &key).await?;
                if !remove_authorization(&mut entries, &prior.authorized_event_ref) {
                    return Err(invalid(
                        "Agent key supersedes names no active authorization dot",
                    ));
                }
                write_key(conn, event, commit, &payload.agent_id, &key_id, entries).await?;
            }
            let key_id = agent_key_id(payload.key_id.as_str())?;
            let key = arkret_wire::derive_agent_key_current_key(&payload.agent_id, &key_id)
                .map_err(|error| invalid(error.to_string()))?;
            let mut entries = load_key(conn, &event.realm_id, &key).await?;
            entries.push(json!({"tag_id":format!("{}:1",event.event_id),"value":event.payload}));
            write_key(conn, event, commit, &payload.agent_id, &key_id, entries).await?;
            if !payload.supersedes.is_empty() {
                let audit = json!({
                    "action": "ak.agent.key.authorize",
                    "outcome": "accepted",
                    "reason_code": arkret_wire::ReasonCode::SUPERSEDED_BY_REPAIRING,
                    "event_id": event.event_id,
                    "commit_id": commit.commit_id,
                    "realm_id": event.realm_id,
                    "agent_id": payload.agent_id,
                    "executed_by": event.executed_by,
                    "supersedes": payload.supersedes,
                });
                sql_query(
                    "INSERT INTO audit_logs(id,actor_id,action,outcome,realm_id,payload,created_at) \
                     VALUES($1,$2,'ak.agent.key.authorize','accepted',$3,$4,$5)",
                )
                .bind::<diesel::sql_types::Uuid, _>(uuid::Uuid::now_v7())
                .bind::<Text, _>(event.actor_id.to_string())
                .bind::<Text, _>(event.realm_id.as_str())
                .bind::<Jsonb, _>(&audit)
                .bind::<Timestamptz, _>(commit.committed_at)
                .execute(&mut *conn)
                .await
                .map_err(PersistenceError::database)?;
            }
        }
        arkret_wire::EventKind::AgentKeyRevoke => {
            let payload: AgentKeyRevokePayload = serde_json::from_value(json!(event.payload))
                .map_err(|error| invalid(error.to_string()))?;
            lock_agent_producer_current(conn, &event.realm_id, &payload.agent_id).await?;
            let key_id = agent_key_id(payload.key_id.as_str())?;
            let key = arkret_wire::derive_agent_key_current_key(&payload.agent_id, &key_id)
                .map_err(|error| invalid(error.to_string()))?;
            let mut entries = load_key(conn, &event.realm_id, &key).await?;
            let observed = entries.len();
            entries.retain(|entry| active_event_id(entry).is_none());
            if entries.len() == observed {
                return Err(invalid(
                    "Agent key revoke names a key with no active authorization",
                ));
            }
            entries.push(json!({"tag_id":format!("{}:1",event.event_id),"value":event.payload}));
            write_key(conn, event, commit, &payload.agent_id, &key_id, entries).await?;
        }
        _ => {}
    }
    Ok(())
}

/// Serialize all key rows for one Agent, including a newly inserted key row.
/// A row lock alone would permit a concurrent authorization to appear after a
/// self Event counted the active key set.
pub(crate) async fn lock_agent_producer_current(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    agent_id: &arkret_wire::DidCoreId,
) -> PersistenceResult<()> {
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>(format!("agent-producer-current:{realm_id}:{agent_id}"))
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(())
}

fn status_transition(current: Option<&str>, expected: &str, next: &str) -> PersistenceResult<()> {
    let actual = current.unwrap_or("uninitialized");
    if actual != expected
        || !matches!(
            (actual, next),
            ("uninitialized", "active")
                | ("active", "paused" | "deactivated")
                | ("paused", "active" | "deactivated")
        )
    {
        return Err(invalid(
            "Agent status transition is not in the registered lifecycle FSM",
        ));
    }
    Ok(())
}

pub(crate) async fn project_agent_status_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let (expected, next) = match event.kind {
        arkret_wire::EventKind::RealmCreate
            if event
                .payload
                .get("object")
                .and_then(|object| object.get("purpose"))
                == Some(&Value::String("agent_control".to_owned())) =>
        {
            ("uninitialized".to_owned(), "active")
        }
        arkret_wire::EventKind::SelfAgentPause => {
            let payload: arkret_models_collaboration::events_payloads::agent::AgentPausePayload =
                serde_json::from_value(json!(event.payload))
                    .map_err(|error| invalid(error.to_string()))?;
            (payload.previous_status, "paused")
        }
        arkret_wire::EventKind::SelfAgentResume => {
            let payload: arkret_models_collaboration::events_payloads::agent::AgentResumePayload =
                serde_json::from_value(json!(event.payload))
                    .map_err(|error| invalid(error.to_string()))?;
            (payload.previous_status, "active")
        }
        arkret_wire::EventKind::SelfAgentDeactivate => {
            let payload: arkret_models_collaboration::events_payloads::agent::AgentDeactivatePayload =
                serde_json::from_value(json!(event.payload))
                    .map_err(|error| invalid(error.to_string()))?;
            (payload.previous_status, "deactivated")
        }
        _ => return Ok(()),
    };
    let actor = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| invalid("Agent lifecycle actor must be an account"))?;
    let agent_id = &actor.principal_id;
    let current_key = arkret_wire::derive_agent_status_current_key(&event.actor_id)
        .map_err(|error| invalid(error.to_string()))?;
    let previous = sql_query(
        "SELECT value FROM agent_status_current_results WHERE realm_id=$1 AND current_key=$2 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&current_key)
    .get_result::<CurrentValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    status_transition(
        previous.as_ref().and_then(|row| row.value.as_str()),
        &expected,
        next,
    )?;
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| invalid("Agent status stream position exceeds i64"))?;
    sql_query(
        "INSERT INTO agent_status_current_results \
         (realm_id,current_key,agent_id,actor_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (realm_id,current_key) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&current_key)
    .bind::<Text, _>(agent_id.as_str())
    .bind::<Jsonb, _>(json!(event.actor_id))
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(json!(next))
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_lifecycle_fsm_rejects_skips_and_terminal_reentry() {
        for (current, expected, next) in [
            (None, "uninitialized", "active"),
            (Some("active"), "active", "paused"),
            (Some("paused"), "paused", "active"),
            (Some("active"), "active", "deactivated"),
            (Some("paused"), "paused", "deactivated"),
        ] {
            status_transition(current, expected, next).unwrap();
        }
        for (current, expected, next) in [
            (None, "uninitialized", "paused"),
            (Some("active"), "paused", "deactivated"),
            (Some("deactivated"), "deactivated", "active"),
        ] {
            assert!(status_transition(current, expected, next).is_err());
        }
    }

    #[test]
    fn agent_key_replacement_removes_only_named_authorize_dot() {
        let old_event =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x11; 32]);
        let other_event =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x22; 32]);
        let mut entries = vec![
            json!({"tag_id":format!("{}:1",old_event),"value":{"verification_method":"did:web:agent.example#old"}}),
            json!({"tag_id":format!("{}:1",other_event),"value":{"verification_method":"did:web:agent.example#other"}}),
            json!({"tag_id":format!("{}:1",arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[0x33;32])),"value":{"revoked_by":"did:web:controller.example"}}),
        ];
        assert!(remove_authorization(&mut entries, &old_event));
        assert_eq!(entries.len(), 2);
        assert_eq!(active_event_id(&entries[0]), Some(other_event.as_str()));
        assert!(active_event_id(&entries[1]).is_none());
        assert!(!remove_authorization(&mut entries, &old_event));
    }

    #[test]
    fn agent_key_dots_sort_numeric_indices_and_reject_duplicates() {
        let event =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x11; 32]);
        let mut entries = vec![
            json!({"tag_id":format!("{event}:10")}),
            json!({"tag_id":format!("{event}:2")}),
        ];
        canonicalize_entries(&mut entries).unwrap();
        assert_eq!(entries[0]["tag_id"], format!("{event}:2"));
        assert_eq!(entries[1]["tag_id"], format!("{event}:10"));
        entries[1] = entries[0].clone();
        assert!(canonicalize_entries(&mut entries).is_err());
        entries[1] = json!({"tag_id":format!("{event}:02")});
        assert!(canonicalize_entries(&mut entries).is_err());
    }
}
