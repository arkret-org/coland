//! Append-only MemberIdentity assertions at the accepting RealmCommit cut.
//! Inner display proofs and replacement edges are verified by consumers.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_identity::{MemberIdentityUpdatePayload, member_identity_effective_set_digest};
use arkret_wire::{CommitStreamRef, Event, EventId, EventKind, RealmCommit, ScopeRef};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::{Value, json};

#[derive(diesel::QueryableByName)]
struct CurrentRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

fn invalid(detail: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.into())
}

/// Fold only digest-bound edges within the already selected exact tuple.
/// The signed raw payloads remain untouched for the expected-state digest.
fn effective_payloads(value: &Value) -> PersistenceResult<Vec<(EventId, Value)>> {
    let assertions = value
        .get("assertions")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("invalid member identity assertion set"))?;
    let mut candidates = BTreeMap::new();
    for assertion in assertions {
        let id = assertion
            .get("tag_id")
            .and_then(Value::as_str)
            .and_then(|tag| tag.strip_suffix(":0"))
            .ok_or_else(|| invalid("invalid member identity assertion dot"))?;
        let event_id = EventId::new(id).map_err(|e| invalid(e.to_string()))?;
        let payload = assertion
            .get("value")
            .ok_or_else(|| invalid("missing identity payload"))?
            .clone();
        let carrier = payload
            .get("identity_payload")
            .ok_or_else(|| invalid("missing identity carrier"))?;
        let digest =
            arkret_canonical::canonical_sha256(carrier).map_err(PersistenceError::database)?;
        candidates.insert(event_id, (payload, digest));
    }
    let mut replaced = BTreeSet::new();
    for (payload, _) in candidates.values() {
        for edge in payload
            .get("replaces")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(id) = edge.get("event_id").and_then(Value::as_str) else {
                continue;
            };
            if let Some((_, digest)) = candidates
                .iter()
                .find(|(key, _)| key.as_str() == id)
                .map(|(_, v)| v)
                && edge.get("payload_digest").and_then(Value::as_str) == Some(digest.as_str())
            {
                replaced.insert(id.to_owned());
            }
        }
    }
    Ok(candidates
        .into_iter()
        .filter(|(id, _)| !replaced.contains(id.as_str()))
        .map(|(id, (payload, _))| (id, payload))
        .collect())
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::MemberIdentityUpdate {
        return Ok(());
    }
    let raw = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let payload: MemberIdentityUpdatePayload = serde_json::from_value(raw.clone())
        .map_err(|e| invalid(format!("invalid member identity payload: {e}")))?;
    if payload.realm_id != event.realm_id
        || payload.member_id != event.actor_id
        || event.executed_by.is_some()
        || !matches!(&event.scope_ref, ScopeRef::Realm { realm_id } if realm_id == &event.realm_id)
        || !matches!(&commit.stream_ref, CommitStreamRef::Realm { realm_id } if realm_id == &event.realm_id)
    {
        return Err(invalid(
            "member identity requires its self-authored exact Realm tuple",
        ));
    }
    let member = arkret_canonical::canonical_json_string(&payload.member_id)
        .map_err(PersistenceError::database)?;
    let previous = sql_query("SELECT value FROM member_identity_updates_current_states WHERE realm_id=$1 AND member_id=$2 AND segment='member_identity' FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&member)
        .get_result::<CurrentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let mut value = previous.map_or_else(|| json!({"assertions": []}), |row| row.value);
    if let Some(expected) = &payload.expected_state_digest {
        let effective = effective_payloads(&value)?;
        let refs = effective
            .iter()
            .map(|(id, payload)| (id, payload))
            .collect::<Vec<_>>();
        let actual =
            member_identity_effective_set_digest(&refs).map_err(PersistenceError::database)?;
        if expected.as_str() != actual {
            return Err(PersistenceError::Conflict(
                "failed_precondition: member_identity_state_mismatch".to_owned(),
            ));
        }
    }
    let assertions = value
        .get_mut("assertions")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid("invalid member identity assertion set"))?;
    assertions.push(json!({"tag_id": format!("{}:0", event.event_id), "value": raw}));
    let mut sorted = assertions
        .iter()
        .map(|entry| {
            let dot = serde_json::from_value::<
                arkret_models_collaboration::exact_current_state::CanonicalEventDot,
            >(entry["tag_id"].clone())
            .map_err(|_| invalid("member identity current contains an invalid Event dot"))?;
            Ok((dot, entry.clone()))
        })
        .collect::<PersistenceResult<Vec<_>>>()?;
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(invalid(
            "member identity current contains duplicate Event dots",
        ));
    }
    *assertions = sorted.into_iter().map(|(_, value)| value).collect();
    sql_query("INSERT INTO member_identity_updates_current_states (realm_id,member_id,segment,current_commit_id,current_stream_position,value,updated_at) VALUES ($1,$2,'member_identity',$3,$4,$5,$6) ON CONFLICT (realm_id,member_id,segment) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(&member)
        .bind::<Text,_>(commit.commit_id.as_str())
        .bind::<BigInt,_>(i64::try_from(commit.stream_position).map_err(|_| invalid("invalid stream position"))?)
        .bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(commit.committed_at)
        .execute(conn).await.map_err(PersistenceError::database)?;
    Ok(())
}
