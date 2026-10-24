//! Durable encrypted exchange controls at one accepted native Sidecar cut.

use arkret_models_collaboration::agent_sidecar::{
    AgentSidecarExchangeControlAssertion, AgentSidecarExchangeControlsValue,
};
use arkret_models_collaboration::events_payloads::sidecar::AgentSidecarExchangeControlPayload;
use arkret_models_collaboration::exact_current_state::CanonicalEventDot;
use arkret_wire::{CommitStreamRef, Event, EventKind, RealmCommit, ScopeRef};
use coland_storage::{ConflictCode, PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension, RunQueryDsl};

#[derive(diesel::QueryableByName)]
struct Current {
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    source_stream_ref: serde_json::Value,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
}

#[derive(diesel::QueryableByName)]
struct Owner {
    #[diesel(sql_type = Jsonb)]
    controller_account_id: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(diesel::QueryableByName)]
struct Attached {
    #[diesel(sql_type = Jsonb)]
    context_ref: serde_json::Value,
}

fn refused(code: ConflictCode, detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("{code}: {detail}"))
}

fn corrupt(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!("stored Sidecar exchange controls: {detail}"))
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    authorize: bool,
) -> PersistenceResult<()> {
    if event.kind != EventKind::AgentSidecarExchangeControl {
        return Ok(());
    }
    let payload: AgentSidecarExchangeControlPayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    payload
        .encrypted_payload
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let stream = CommitStreamRef::Sidecar {
        realm_id: event.realm_id.clone(),
        sidecar_id: payload.sidecar_id.clone(),
    };
    if event.scope_ref
        != (ScopeRef::Sidecar {
            realm_id: event.realm_id.clone(),
            sidecar_id: payload.sidecar_id.clone(),
        })
        || commit.stream_ref != stream
        || commit.realm_id != event.realm_id
        || commit.event_ref != event.event_id
        || event.executed_by.is_some()
        || event.applet_id.is_some()
    {
        return Err(PersistenceError::SchemaViolation(
            "Sidecar control requires its exact native stream and direct controller".to_owned(),
        ));
    }
    let context =
        serde_json::to_value(&payload.source_context_ref).map_err(PersistenceError::database)?;
    let digest = arkret_canonical::canonical_sha256(&payload.source_context_ref)
        .map_err(PersistenceError::database)?;
    if authorize {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
        let owner = diesel::sql_query(
            "SELECT controller_account_id,value FROM sidecar_current_states \
             WHERE realm_id=$1 AND sidecar_id=$2 FOR SHARE",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<Text, _>(payload.sidecar_id.as_str())
        .get_result::<Owner>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| {
            refused(
                ConflictCode::CapabilityDenied,
                "Sidecar controller is unavailable",
            )
        })?;
        let account = event.actor_id.as_account_id().ok_or_else(|| {
            refused(
                ConflictCode::CapabilityDenied,
                "Sidecar control has no controller Account",
            )
        })?;
        if owner.controller_account_id
            != serde_json::to_value(account).map_err(PersistenceError::database)?
            || owner.value["state"] != "active"
            || crate::member_state_admission::locked_membership(
                conn,
                &event.realm_id,
                &event.actor_id,
            )
            .await?
                != "join"
        {
            return Err(refused(
                ConflictCode::CapabilityDenied,
                "Sidecar controller is unavailable",
            ));
        }
        let attached = diesel::sql_query(
            "SELECT context_ref FROM sidecar_context_current_states \
             WHERE realm_id=$1 AND sidecar_id=$2 AND context_ref_digest=$3 FOR SHARE",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<Text, _>(payload.sidecar_id.as_str())
        .bind::<Text, _>(&digest)
        .get_result::<Attached>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if attached.is_none_or(|attached| attached.context_ref != context) {
            return Err(refused(
                ConflictCode::FailedPrecondition,
                "Sidecar source context is not attached",
            ));
        }
        crate::mls_group_current_states::require_mls_send_gate_in_connection(conn, event).await?;
    }
    let source = serde_json::to_value(&stream).map_err(PersistenceError::database)?;
    let position = i64::try_from(commit.stream_position).map_err(PersistenceError::database)?;
    let previous = diesel::sql_query(
        "SELECT value,source_stream_ref,current_stream_position \
         FROM sidecar_exchange_controls_current_states \
         WHERE realm_id=$1 AND sidecar_id=$2 AND context_ref_digest=$3 FOR UPDATE",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.sidecar_id.as_str())
    .bind::<Text, _>(&digest)
    .get_result::<Current>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let current = match previous {
        Some(previous) => {
            if previous.source_stream_ref != source || previous.current_stream_position >= position
            {
                return Err(refused(
                    ConflictCode::FailedPrecondition,
                    "Sidecar control does not extend its current stream",
                ));
            }
            serde_json::from_value::<AgentSidecarExchangeControlsValue>(previous.value)
                .map_err(corrupt)?
        }
        None => AgentSidecarExchangeControlsValue::new(Vec::new()).map_err(corrupt)?,
    };
    current
        .validate_for_context(&payload.sidecar_id, &payload.source_context_ref)
        .map_err(corrupt)?;
    let current = current
        .with_assertion(AgentSidecarExchangeControlAssertion {
            tag_id: CanonicalEventDot::new(event.event_id.clone(), 0).map_err(corrupt)?,
            value: payload.clone(),
        })
        .map_err(corrupt)?;
    let changed = diesel::sql_query(
        "INSERT INTO sidecar_exchange_controls_current_states \
         (realm_id,sidecar_id,context_ref_digest,context_ref,current_commit_id,current_stream_position,source_stream_ref,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT(sidecar_id,context_ref_digest) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE sidecar_exchange_controls_current_states.realm_id=EXCLUDED.realm_id \
           AND sidecar_exchange_controls_current_states.context_ref=EXCLUDED.context_ref \
           AND sidecar_exchange_controls_current_states.source_stream_ref=EXCLUDED.source_stream_ref",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.sidecar_id.as_str())
    .bind::<Text, _>(digest)
    .bind::<Jsonb, _>(context)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(source)
    .bind::<Jsonb, _>(serde_json::to_value(current).map_err(PersistenceError::database)?)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(refused(
            ConflictCode::FailedPrecondition,
            "Sidecar control changes its source identity",
        ));
    }
    Ok(())
}

/// Install a complete source-signed set before its private native tail arrives.
/// The set can only grow; a newer snapshot never retracts a held Event dot.
pub(crate) async fn install_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    entry: &arkret_wire::CurrentState,
    installed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let arkret_wire::CurrentState::Value {
        selector:
            arkret_wire::CurrentSelector::AgentSidecarExchangeControls {
                sidecar_id,
                source_context_ref,
            },
        source_stream_ref,
        revision,
        value,
    } = entry
    else {
        return Ok(());
    };
    let current: AgentSidecarExchangeControlsValue =
        serde_json::from_value(value.clone()).map_err(corrupt)?;
    current
        .validate_for_context(sidecar_id, source_context_ref)
        .map_err(corrupt)?;
    if current.assertions().is_empty()
        || source_stream_ref
            != &(CommitStreamRef::Sidecar {
                realm_id: realm.clone(),
                sidecar_id: sidecar_id.clone(),
            })
    {
        return Err(corrupt(
            "snapshot controls have no assertion or cross their native stream",
        ));
    }
    let digest = arkret_canonical::canonical_sha256(source_context_ref)
        .map_err(PersistenceError::database)?;
    let previous = diesel::sql_query(
        "SELECT value,source_stream_ref,current_stream_position \
         FROM sidecar_exchange_controls_current_states \
         WHERE realm_id=$1 AND sidecar_id=$2 AND context_ref_digest=$3 FOR UPDATE",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(sidecar_id.as_str())
    .bind::<Text, _>(&digest)
    .get_result::<Current>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if let Some(previous) = previous {
        let previous: AgentSidecarExchangeControlsValue =
            serde_json::from_value(previous.value).map_err(corrupt)?;
        if previous
            .assertions()
            .iter()
            .any(|assertion| !current.assertions().contains(assertion))
        {
            return Err(refused(
                ConflictCode::FailedPrecondition,
                "Sidecar snapshot retracts a held control assertion",
            ));
        }
    }
    let changed = diesel::sql_query(
        "INSERT INTO sidecar_exchange_controls_current_states \
         (realm_id,sidecar_id,context_ref_digest,context_ref,current_commit_id,current_stream_position,source_stream_ref,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(sidecar_id,context_ref_digest) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE sidecar_exchange_controls_current_states.realm_id=EXCLUDED.realm_id \
           AND sidecar_exchange_controls_current_states.context_ref=EXCLUDED.context_ref \
           AND sidecar_exchange_controls_current_states.source_stream_ref=EXCLUDED.source_stream_ref \
           AND (sidecar_exchange_controls_current_states.current_stream_position<EXCLUDED.current_stream_position \
             OR (sidecar_exchange_controls_current_states.current_stream_position=EXCLUDED.current_stream_position \
               AND sidecar_exchange_controls_current_states.current_commit_id=EXCLUDED.current_commit_id \
               AND sidecar_exchange_controls_current_states.value=EXCLUDED.value))",
    )
    .bind::<Text, _>(realm.as_str())
    .bind::<Text, _>(sidecar_id.as_str())
    .bind::<Text, _>(digest)
    .bind::<Jsonb, _>(serde_json::to_value(source_context_ref).map_err(PersistenceError::database)?)
    .bind::<Text, _>(revision.commit_id.as_str())
    .bind::<BigInt, _>(i64::try_from(revision.stream_position).map_err(PersistenceError::database)?)
    .bind::<Jsonb, _>(serde_json::to_value(source_stream_ref).map_err(PersistenceError::database)?)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(installed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(refused(
            ConflictCode::FailedPrecondition,
            "Sidecar snapshot control revision conflicts",
        ));
    }
    Ok(())
}
