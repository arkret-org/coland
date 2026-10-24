//! MLS readiness follows the desired authority cut; it never contributes refs.

use arkret_wire::{ActorId, DidCoreId, MlsGroupValue, ScopeRef};
use serde_json::Value;

use super::{
    AsyncPgConnection, Binary, Jsonb, OptionalExtension, PersistenceError, PersistenceResult,
    QueryableByName, RunQueryDsl, Text, sql_query,
};
use crate::sidecar_authority_cut::SidecarParticipantAuthorityCut;

#[derive(QueryableByName)]
struct GroupRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = Binary)]
    public_state: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

#[derive(QueryableByName)]
struct KeyRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

/// A matching public leaf alone is insufficient. Its still authorized runtime
/// endpoint must also have consumed the accepted Welcome for this exact group.
pub(crate) async fn effective_agents_in_connection(
    conn: &mut AsyncPgConnection,
    cut: &SidecarParticipantAuthorityCut,
) -> PersistenceResult<Vec<DidCoreId>> {
    let scope = ScopeRef::Sidecar {
        realm_id: cut.realm_id.clone(),
        sidecar_id: cut.sidecar_id.clone(),
    };
    let scope_key = crate::mls_group_current_states::scope_key(&scope)?;
    let group = sql_query("SELECT g.value,g.public_state,e.envelope FROM mls_group_current_states g \
        JOIN realm_commits c ON c.realm_id=g.realm_id AND c.commit_id=g.current_commit_id AND c.stream_position=g.current_stream_position \
        JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
        WHERE g.scope_key=$1 AND c.stream_ref=jsonb_build_object('kind','sidecar','realm_id',$2,'sidecar_id',$3)")
        .bind::<Text,_>(&scope_key).bind::<Text,_>(cut.realm_id.as_str()).bind::<Text,_>(cut.sidecar_id.as_str())
        .get_result::<GroupRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(group) = group else {
        return Ok(Vec::new());
    };
    let event: arkret_wire::Event =
        serde_json::from_value(group.envelope).map_err(PersistenceError::database)?;
    let binding = match event.kind {
        arkret_wire::EventKind::MlsGenesis => serde_json::from_value::<
            arkret_models_collaboration::events_payloads::MlsGenesisPayload,
        >(
            serde_json::to_value(event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?
        .governance_binding,
        arkret_wire::EventKind::MlsCommit => serde_json::from_value::<
            arkret_models_collaboration::events_payloads::MlsCommitPayload,
        >(
            serde_json::to_value(event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?
        .governance_binding()
        .clone(),
        _ => {
            return Err(PersistenceError::SchemaViolation(
                "Sidecar MLS current has no accepted MLS source".into(),
            ));
        }
    };
    if binding.effective_scope() != &scope
        || binding.sidecar_binding().is_none_or(|binding| {
            binding.participant_authority_digest != cut.participant_authority_digest
                || binding.authority_stream_head != cut.authority_stream_head
        })
    {
        return Ok(Vec::new());
    }
    let current: MlsGroupValue =
        serde_json::from_value(group.value).map_err(PersistenceError::database)?;
    if !crate::sidecar_mls_readiness::tree_authorized_in_connection(
        conn,
        cut,
        &current,
        &group.public_state,
        None,
    )
    .await?
    {
        return Ok(Vec::new());
    }
    let group_id = scope
        .canonical_mls_group_id()
        .map_err(PersistenceError::database)?;
    let leaves = arkret_mls::MlsPublicGroupTracker::restore(
        &group.public_state,
        group_id.as_str(),
        current.epoch,
    )
    .and_then(|tracker| tracker.leaves())
    .map_err(PersistenceError::database)?;
    let mut effective = Vec::new();
    for agent in &cut.desired_agent_ids {
        let actor = ActorId::account(arkret_wire::AccountId::new(
            agent.clone(),
            cut.controller_account_id.station_id.clone(),
        ));
        let keys = sql_query("SELECT k.value FROM agent_key_current_states k JOIN agent_status_current_states s ON s.realm_id=k.realm_id AND s.agent_id=k.agent_id \
            JOIN realm_commits c ON c.realm_id=k.realm_id AND c.commit_id=k.current_commit_id AND c.stream_position=k.current_stream_position \
            JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
            WHERE s.actor_id=$2::jsonb AND k.agent_id=$1 ORDER BY k.agent_key_id")
            .bind::<Text,_>(agent.as_str()).bind::<Text,_>(actor.to_string())
            .load::<KeyRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        let mut ready = false;
        for key in keys {
            let Some(entries) = key.value.get("authorizations").and_then(Value::as_array) else {
                return Err(PersistenceError::SchemaViolation(
                    "runtime current has no authorization dots".into(),
                ));
            };
            for entry in entries {
                if entry
                    .pointer("/value/verification_method")
                    .and_then(Value::as_str)
                    .is_none()
                {
                    continue;
                }
                let authorization: arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload = serde_json::from_value(entry["value"].clone()).map_err(PersistenceError::database)?;
                if authorization
                    .expires_at
                    .is_some_and(|expiry| expiry <= chrono::Utc::now())
                {
                    continue;
                }
                let value = serde_json::to_value(&authorization.public_key)
                    .map_err(PersistenceError::database)?;
                let Some(key_bytes) = value.get("key").and_then(Value::as_str) else {
                    continue;
                };
                if !leaves
                    .iter()
                    .any(|leaf| leaf.actor_id == actor && leaf.signature_key.as_str() == key_bytes)
                {
                    continue;
                }
                let Some(dot) = entry
                    .get("tag_id")
                    .and_then(Value::as_str)
                    .and_then(|tag| tag.strip_suffix(":1"))
                else {
                    continue;
                };
                let event = arkret_wire::EventId::new(dot).map_err(PersistenceError::database)?;
                let consumed = crate::sidecar_mls_readiness::consumed_endpoint_in_connection(
                    conn,
                    &scope,
                    &actor,
                    &cut.controller_account_id,
                    &arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
                        verification_method: authorization.verification_method.clone(),
                    },
                    &event,
                    &arkret_wire::Base64UrlString::new(key_bytes.to_owned())
                        .map_err(PersistenceError::database)?,
                    current.epoch,
                )
                .await?;
                ready |= consumed;
            }
        }
        if ready {
            effective.push(agent.clone());
        }
    }
    Ok(effective)
}
