//! Account Device governance commands on the private Realm control stream.
use arkret_models_integration::*;
use arkret_wire::{
    ActorId, CommittedEventRef, CurrentRevision, Event, EventKind, RealmCommit, ScopeRef,
};
use coland_storage::{EventApprovalCommit, PersistenceError};
use serde_json::{Value, json};

use crate::realm_actor_control::{current_source, write_current};
use crate::{AsyncPgConnection, PgTransactionError};

fn invalid(detail: impl std::fmt::Display) -> PgTransactionError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}")).into()
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, PgTransactionError> {
    serde_json::from_value(value).map_err(invalid)
}
fn revision(source: &CommittedEventRef) -> CurrentRevision {
    CurrentRevision {
        commit_id: source.commit_id.clone(),
        stream_position: source.stream_position,
    }
}
pub(crate) fn is_command(event: &Event) -> bool {
    matches!(
        event.kind,
        EventKind::RealmActorStatusSet | EventKind::RealmActorRecoverySet
    ) && event.actor_id.as_account_id().is_some()
}
/// Called only after the ordinary unit verified the local or forwarded real Device.
pub(crate) async fn commit(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    prepared: Option<&EventApprovalCommit>,
) -> Result<(), PgTransactionError> {
    if !is_command(event) {
        return Ok(());
    }
    if event.executed_by.is_some()
        || event.scope_ref
            != (ScopeRef::RealmControl {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(invalid(
            "governance requires a direct Account Device and private scope",
        ));
    }
    let actor: ActorId = decode(
        event
            .payload
            .get("target_actor_id")
            .cloned()
            .ok_or_else(|| invalid("target absent"))?,
    )?;
    if actor
        .as_realm_actor_id()
        .is_none_or(|a| a.realm_id != event.realm_id)
    {
        return Err(invalid("governance target belongs to another Realm"));
    }
    crate::realm_actor_control::creation_source(conn, &actor).await?;
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read_for_event(conn, event).await?;
    cut.require_realm_actor_management(conn, event, commit, prepared, &actor)
        .await?;
    let recovery_selector = json!({"kind":"realm_actor_recovery","actor_id":actor});
    let (recovery, recovery_ref) = current_source(conn, &actor, recovery_selector.clone()).await?;
    let mut recovery: RealmActorRecoveryValue = decode(recovery)?;
    let owner_selector = json!({"kind":"realm_actor_status","actor_id":actor,"gate":"owner"});
    let (owner, _) = current_source(conn, &actor, owner_selector).await?;
    let governance_selector =
        json!({"kind":"realm_actor_status","actor_id":actor,"gate":"governance"});
    let (governance, governance_ref) =
        current_source(conn, &actor, governance_selector.clone()).await?;
    let accepted = CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };
    let cancel;
    match event.kind {
        EventKind::RealmActorStatusSet => {
            let payload: RealmActorStatusSetPayload = decode(json!(event.payload))?;
            if payload.gate != RealmActorStatusSetPayloadGate::Governance
                || payload.expected_revision != revision(&governance_ref)
                || governance == "retired"
                || (owner == "retired" && payload.state != RealmActorStatusSetPayloadState::Retired)
            {
                return Err(invalid("governance gate, CAS or terminal state differs"));
            }
            cancel = payload.state == RealmActorStatusSetPayloadState::Retired;
            write_current(
                conn,
                &actor,
                governance_selector,
                json!(payload.state),
                commit,
            )
            .await?;
        }
        EventKind::RealmActorRecoverySet => {
            let payload: RealmActorRecoverySetPayload = decode(json!(event.payload))?;
            let (_, manager_ref) = current_source(
                conn,
                &actor,
                json!({"kind":"realm_actor_manager","actor_id":actor}),
            )
            .await?;
            if payload.expected_recovery_revision != revision(&recovery_ref)
                || payload.expected_manager_revision != revision(&manager_ref)
                || payload.enabled == recovery.enabled
                || ((owner == "retired" || governance == "retired") && payload.enabled)
            {
                return Err(invalid(
                    "recovery permission CAS, value or terminal state differs",
                ));
            }
            recovery.enabled = payload.enabled;
            cancel = true;
        }
        _ => unreachable!("closed governance command"),
    }
    if cancel {
        if let Some(pending) = &recovery.pending {
            crate::realm_actor_recovery::terminal(
                conn,
                &actor,
                &pending.begin_ref,
                RealmActorRecoveryState::Cancelled,
                &accepted,
            )
            .await?;
            recovery.pending = None;
        }
        write_current(conn, &actor, recovery_selector, json!(recovery), commit).await?;
    }
    // Preparation preserves the original signature list order; reconstruct the exact
    // registered self submission, never a normalized Event-only digest.
    let request =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
            arkret_wire::EventAdmissionSubmission {
                event: event.clone(),
                approval_signatures: prepared
                    .map(|p| p.methods.iter().map(|m| m.signature.clone()).collect()),
            },
        );
    let digest =
        arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&request).map_err(invalid)?)
            .map_err(invalid)?;
    let outcome = arkret_wire::AuthoritySubmitResponseBody::Accepted {
        status: arkret_wire::AuthorityCommitStatus::Committed,
        commit: commit.clone(),
    };
    crate::realm_actor_material::retain_outcome(
        conn,
        event,
        &actor,
        &digest,
        &outcome,
        commit.committed_at,
    )
    .await?;
    Ok(())
}
