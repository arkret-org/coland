//! Recording Start pins one actual accepted current MLS state under its native cut.
use arkret_models_collaboration::events_payloads::MlsGenesisPayload;
use arkret_models_collaboration::events_payloads::call::CallRecordingStartPayload;
use arkret_models_crypto::MlsCommitPayload;
use arkret_wire::{
    CommitStreamRef, CommittedEventFullView, Event, EventKind, MlsGroupValue, RealmCommit,
};
use coland_storage::{ConflictCode, PersistenceError, PersistenceResult};

use crate::AsyncPgConnection;

fn unavailable(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "{}: recording key source {detail}",
        arkret_wire::ErrorCode::RevisionUnavailable.as_str()
    ))
}

fn refused(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "{}: recording key source {detail}",
        ConflictCode::FailedPrecondition
    ))
}

async fn original(
    conn: &mut AsyncPgConnection,
    id: &arkret_wire::EventId,
) -> PersistenceResult<CommittedEventFullView> {
    let source = crate::committed_disclosure::accepted_full_event_in_connection(conn, id)
        .await?
        .ok_or_else(|| unavailable("has no retained accepted original"))?;
    source
        .validate_shape()
        .map_err(PersistenceError::database)?;
    if crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
        conn,
        &source.event,
        &source.commit,
    )
    .await?
    .is_none()
    {
        return Err(unavailable("has no verified original producer source"));
    }
    Ok(source)
}

fn same_scope(
    source: &CommittedEventFullView,
    event: &Event,
    accepting: &RealmCommit,
) -> PersistenceResult<()> {
    let stream =
        CommitStreamRef::from_scope(&event.scope_ref, None).map_err(PersistenceError::database)?;
    if source.event.realm_id != event.realm_id
        || source.event.scope_ref != event.scope_ref
        || source.commit.realm_id != event.realm_id
        || source.commit.stream_ref != stream
        || accepting.stream_ref != stream
        || source.commit.stream_position >= accepting.stream_position
    {
        return Err(refused(
            "differs from the actual scope or accepting predecessor cut",
        ));
    }
    Ok(())
}

fn require_genesis(
    original: &CommittedEventFullView,
    group: &MlsGroupValue,
) -> PersistenceResult<()> {
    if original.event.kind != EventKind::MlsGenesis
        || original.event.event_id != group.genesis_event_ref
    {
        return Err(unavailable(
            "immutable Genesis is not its native accepted original",
        ));
    }
    let payload: MlsGenesisPayload = serde_json::from_value(
        serde_json::to_value(&original.event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    if payload.mls_group_id().map_err(PersistenceError::database)?
        != group
            .effective_scope
            .canonical_mls_group_id()
            .map_err(PersistenceError::database)?
    {
        return Err(unavailable("immutable Genesis has another MLS group"));
    }
    Ok(())
}

/// The caller already holds the Realm authorization cut used by Start's
/// capability, Call, consent and lifecycle gates. This is internal provenance
/// verification; it does not grant the recorder any historical Event or key read.
pub(super) async fn require_current(
    conn: &mut AsyncPgConnection,
    event: &Event,
    accepting: &RealmCommit,
    opening: &CallRecordingStartPayload,
) -> PersistenceResult<()> {
    let key = opening
        .capture_metadata
        .key_ref
        .as_ref()
        .ok_or_else(|| refused("is missing"))?;
    let selected = key
        .group_state_ref
        .event_id()
        .map_err(PersistenceError::database)?;
    let scope_key = crate::mls_group_current_states::scope_key(&event.scope_ref)?;
    let group = crate::mls_group_current_states::locked_group(conn, &scope_key)
        .await?
        .ok_or_else(|| refused("has no accepted current MLS group"))?;
    if group.realm_id != event.realm_id
        || group.value.effective_scope != event.scope_ref
        || selected != group.value.current_mls_commit_event_ref
    {
        return Err(refused("is not this scope's exact accepted winning state"));
    }
    let source = original(conn, &selected).await?;
    same_scope(&source, event, accepting)?;
    // A membership/key-access update may cover mls_group without replacing Q.
    // Its current row revision is not Q's creation Commit.
    if selected == group.value.genesis_event_ref {
        require_genesis(&source, &group.value)?;
        let payload: MlsGenesisPayload = serde_json::from_value(
            serde_json::to_value(&source.event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
        if group.value.epoch != 0 || payload.ratchet_tree_ref != group.value.public_tree_ref {
            return Err(unavailable(
                "Genesis does not match its winning public state",
            ));
        }
    } else {
        if source.event.kind != EventKind::MlsCommit {
            return Err(unavailable("winning state is not an accepted MLS Commit"));
        }
        let payload: MlsCommitPayload = serde_json::from_value(
            serde_json::to_value(&source.event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(PersistenceError::database)?;
        if payload.next_epoch() != group.value.epoch
            || payload.ratchet_tree_ref() != &group.value.public_tree_ref
            || payload.mls_group_id().map_err(PersistenceError::database)?
                != event
                    .scope_ref
                    .canonical_mls_group_id()
                    .map_err(PersistenceError::database)?
        {
            return Err(unavailable(
                "Commit does not match its winning public state",
            ));
        }
        let genesis = original(conn, &group.value.genesis_event_ref).await?;
        same_scope(&genesis, event, accepting)?;
        require_genesis(&genesis, &group.value)?;
        if genesis.commit.stream_position >= source.commit.stream_position {
            return Err(unavailable("winning Commit precedes its immutable Genesis"));
        }
    }
    Ok(())
}
