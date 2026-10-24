//! Owner status and Device generation writes by the current control method.
use arkret_models_integration::*;
use arkret_wire::{CommittedEventRef, CurrentRevision, EventKind, ScopeRef};
use coland_storage::{AppletControlCarrier, AuthorityCommitTransaction, PersistenceError};
use serde_json::json;

use crate::realm_actor_control::{current_source, write_current};
use crate::{AsyncPgConnection, PgTransactionError};

fn invalid(error: impl std::fmt::Display) -> PgTransactionError {
    PersistenceError::Conflict(format!("failed_precondition: {error}")).into()
}
fn decode<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, PgTransactionError> {
    serde_json::from_value(value).map_err(invalid)
}
fn revision(source: &CommittedEventRef) -> CurrentRevision {
    CurrentRevision {
        commit_id: source.commit_id.clone(),
        stream_position: source.stream_position,
    }
}

pub(crate) async fn admit(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    carrier: &AppletControlCarrier,
    publication: Option<&arkret_models_identity::ResolutionCommitment>,
    manager: Option<&coland_storage::AppletEventProducerGuard>,
    prepared: Option<&coland_storage::EventApprovalCommit>,
    digest: &arkret_wire::Hash,
) -> Result<arkret_wire::AuthoritySubmitResponseBody, PgTransactionError> {
    let event = &transaction.event;
    let commit = &transaction.commit;
    let actor = &event.actor_id;
    event.validate_for_submit_structural().map_err(invalid)?;
    if !matches!(
        event.kind,
        EventKind::RealmActorStatusSet
            | EventKind::RealmActorDevicesReset
            | EventKind::RealmActorControlUpdate
            | EventKind::RealmActorManagerChange
            | EventKind::DeviceRevoke
    ) || actor != &carrier.actor_id
        || event.executed_by.is_some()
        || event.authorization_ref.is_some()
        || event.scope_ref
            != (ScopeRef::RealmControl {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(invalid(
            "owner control requires its exact subject and private command",
        ));
    }
    let current = crate::realm_actor_control_transport::current_carrier(
        conn,
        actor,
        &transaction.expected_authority.service_id,
        commit.committed_at,
    )
    .await?;
    if &current != carrier {
        return Err(invalid("owner control transport changed"));
    }
    if let Some(original) =
        crate::committed_disclosure::accepted_full_event_in_connection(conn, &event.event_id)
            .await?
    {
        if original.event != *event {
            return Err(invalid(
                "duplicate_conflict: owner control original differs",
            ));
        }
        let stored = arkret_wire::AuthoritySubmitResponseBody::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Committed,
            commit: original.commit.clone(),
        };
        crate::realm_actor_material::retain_outcome(
            conn,
            event,
            actor,
            digest,
            &stored,
            original.commit.committed_at,
        )
        .await?;
        return Ok(arkret_wire::AuthoritySubmitResponseBody::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Duplicate,
            commit: original.commit,
        });
    }
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, &event.realm_id, actor)
            .await?;
    cut.require_open_lifecycle(event)?;
    let creation = crate::realm_actor_control::creation_source(conn, actor).await?;
    if event.applet_id.as_ref() != Some(&creation.applet_id) {
        return Err(invalid("owner control Applet differs"));
    }
    let fact =
        crate::realm_actor_control_source::signer_fact(conn, event, commit.committed_at).await?;
    crate::agent_producer_signer_keys::validate_producer_fact_binding(event, commit, Some(&fact))?;
    let recovery_selector = json!({"kind":"realm_actor_recovery","actor_id":actor});
    let (recovery, _) = current_source(conn, actor, recovery_selector.clone()).await?;
    let mut recovery: RealmActorRecoveryValue = decode(recovery)?;
    let owner_selector = json!({"kind":"realm_actor_status","actor_id":actor,"gate":"owner"});
    let (owner, owner_ref) = current_source(conn, actor, owner_selector.clone()).await?;
    let (governance, _) = current_source(
        conn,
        actor,
        json!({"kind":"realm_actor_status","actor_id":actor,"gate":"governance"}),
    )
    .await?;
    let accepted = CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };
    let mut writes = Vec::new();
    crate::approval_admission::validate_candidate(event, commit, prepared)?;
    let revoke = if event.kind == EventKind::DeviceRevoke {
        Some(crate::realm_actor_device_revoke::prepare(conn, event, &accepted).await?)
    } else {
        None
    };
    match event.kind {
        EventKind::RealmActorManagerChange => {
            writes.extend(
                crate::realm_actor_manager::admit(
                    conn,
                    transaction,
                    publication,
                    manager.ok_or_else(|| invalid("receiving Service document unavailable"))?,
                    prepared,
                )
                .await?,
            );
        }
        EventKind::DeviceRevoke => {}
        EventKind::RealmActorControlUpdate => {
            let payload: RealmActorControlUpdatePayload = decode(json!(event.payload))?;
            let control = crate::realm_actor_control_source::current(conn, actor).await?;
            if recovery.pending.is_some()
                || owner == "retired"
                || governance == "retired"
                || payload.expected_revision != revision(&control.source)
                || publication != Some(&payload.next_resolution)
            {
                return Err(invalid(
                    "normal control rotation current CAS, publication or state differs",
                ));
            }
            arkret_identity::verify_realm_actor_control_successor(
                actor,
                &control.value.resolution,
                &control.value.control_method_kid,
                &payload,
                commit.committed_at,
            )
            .map_err(invalid)?;
            writes.push((
                json!({"kind":"realm_actor_control","actor_id":actor}),
                json!(RealmActorControlValue {
                    resolution: arkret_models_identity::PrincipalResolutionProjection {
                        did: payload.next_resolution.did,
                        method_history_head: payload.next_resolution.method_history_head,
                        version_id: payload.next_resolution.version_id,
                        resolution_event_ref: event.event_id.to_string(),
                        updated_at: event.created_at
                    },
                    control_method_kid: payload.next_control_method_kid,
                }),
            ));
        }
        EventKind::RealmActorStatusSet => {
            let payload: RealmActorStatusSetPayload = decode(json!(event.payload))?;
            if payload.target_actor_id != *actor
                || payload.gate != RealmActorStatusSetPayloadGate::Owner
                || payload.expected_revision != revision(&owner_ref)
                || owner == "retired"
                || (payload.state == RealmActorStatusSetPayloadState::Active
                    && (recovery.pending.is_some() || governance == "retired"))
            {
                return Err(invalid(
                    "owner gate target, CAS, pending recovery or terminal state differs",
                ));
            }
            if payload.state == RealmActorStatusSetPayloadState::Retired {
                if let Some(pending) = &recovery.pending {
                    crate::realm_actor_recovery::terminal(
                        conn,
                        actor,
                        &pending.begin_ref,
                        RealmActorRecoveryState::Cancelled,
                        &accepted,
                    )
                    .await?;
                    recovery.pending = None;
                }
                writes.push((recovery_selector, json!(recovery)));
            }
            writes.push((owner_selector, json!(payload.state)));
        }
        EventKind::RealmActorDevicesReset => {
            let payload: RealmActorDevicesResetPayload = decode(json!(event.payload))?;
            let selector = json!({"kind":"realm_actor_device_generation","actor_id":actor});
            let (generation, source) = current_source(conn, actor, selector.clone()).await?;
            let generation: RealmActorDeviceGenerationValue = decode(generation)?;
            if recovery.pending.is_some()
                || owner == "retired"
                || governance == "retired"
                || payload.expected_revision != revision(&source)
                || payload.expected_generation != generation.current_device_generation_ref
                || payload.expected_generation.checked_add(1) != Some(payload.new_generation)
            {
                return Err(invalid(
                    "Device reset generation CAS, recovery or terminal gate differs",
                ));
            }
            crate::realm_actor_recovery::inventory(
                conn,
                actor,
                payload.expected_generation,
                &accepted,
            )
            .await?;
            writes.push((
                selector,
                json!(RealmActorDeviceGenerationValue {
                    current_device_generation_ref: payload.new_generation
                }),
            ));
        }
        _ => unreachable!("closed owner command"),
    }
    crate::authority_commit::queue_event_in_connection(conn, event, commit.committed_at).await?;
    if !matches!(
        crate::authority_commit::commit_verified_realm_owner_in_connection(
            conn,
            transaction,
            prepared
        )
        .await?,
        coland_storage::AuthorityCommitWriteOutcome::Committed
    ) {
        return Err(invalid("owner control head or governance changed"));
    }
    crate::agent_producer_signer_keys::retain_prepared_applet_in_connection(
        conn, event, commit, &fact,
    )
    .await?;
    for (selector, value) in writes {
        write_current(conn, actor, selector, value, commit).await?;
    }
    if let Some(revoke) = revoke {
        crate::realm_actor_device_revoke::retain(conn, transaction, digest, revoke).await?;
    }
    let outcome = arkret_wire::AuthoritySubmitResponseBody::Accepted {
        status: arkret_wire::AuthorityCommitStatus::Committed,
        commit: commit.clone(),
    };
    crate::realm_actor_material::retain_outcome(
        conn,
        event,
        actor,
        digest,
        &outcome,
        commit.committed_at,
    )
    .await?;
    Ok(outcome)
}
