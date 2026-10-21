//! Management handover keeps the Realm identity and transfers native control.
use arkret_models_integration::*;
use arkret_wire::{CommittedEventRef, CurrentRevision, EventKind};
use coland_storage::{
    AppletEventProducerGuard, AuthorityCommitTransaction, EventApprovalCommit, PersistenceError,
};
use diesel::sql_types::{Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};

use crate::realm_actor_control::current_source;
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

pub(crate) async fn admit(
    conn: &mut AsyncPgConnection,
    transaction: &AuthorityCommitTransaction,
    publication: Option<&arkret_models_identity::ResolutionCommitment>,
    service: &AppletEventProducerGuard,
    prepared: Option<&EventApprovalCommit>,
) -> Result<Vec<(Value, Value)>, PgTransactionError> {
    let event = &transaction.event;
    let actor = &event.actor_id;
    let commit = &transaction.commit;
    let payload: RealmActorManagerChangePayload = decode(json!(event.payload))?;
    let control = crate::realm_actor_control_source::current(conn, actor).await?;
    let manager_selector = json!({"kind":"realm_actor_manager","actor_id":actor});
    let (manager, manager_ref) = current_source(conn, actor, manager_selector.clone()).await?;
    let manager: RealmActorManagerValue = decode(manager)?;
    let (recovery, _) = current_source(
        conn,
        actor,
        json!({"kind":"realm_actor_recovery","actor_id":actor}),
    )
    .await?;
    let recovery: RealmActorRecoveryValue = decode(recovery)?;
    let (owner, _) = current_source(
        conn,
        actor,
        json!({"kind":"realm_actor_status","actor_id":actor,"gate":"owner"}),
    )
    .await?;
    let (governance, _) = current_source(
        conn,
        actor,
        json!({"kind":"realm_actor_status","actor_id":actor,"gate":"governance"}),
    )
    .await?;
    let generation_selector = json!({"kind":"realm_actor_device_generation","actor_id":actor});
    let (generation, generation_ref) =
        current_source(conn, actor, generation_selector.clone()).await?;
    let generation: RealmActorDeviceGenerationValue = decode(generation)?;
    if owner != "paused"
        || governance == "retired"
        || recovery.pending.is_some()
        || manager.service_id == payload.new_service_id
        || manager.binding_ref != manager_ref
        || payload.expected_manager_revision != revision(&manager_ref)
        || payload.expected_control_revision != revision(&control.source)
        || payload.expected_device_generation_revision != revision(&generation_ref)
        || payload.expected_generation != generation.current_device_generation_ref
        || payload.expected_generation.checked_add(1) != Some(payload.new_generation)
        || control.source.stream_position <= manager_ref.stream_position
        || control.current_event.kind != EventKind::RealmActorControlUpdate
        || publication != Some(&payload.next_resolution)
    {
        return Err(invalid(
            "manager handover gates, current revisions or publication differ",
        ));
    }
    let (binding_event, _) =
        crate::realm_actor_control_source::original(conn, &manager_ref).await?;
    let (resolution, method) = match binding_event.kind {
        EventKind::RealmActorCreate => {
            let original: RealmActorCreatePayload = decode(json!(binding_event.payload))?;
            if original.actor_id != *actor || original.service_id != manager.service_id {
                return Err(invalid("manager binding creation differs"));
            }
            (original.initial_resolution, original.control_method_kid)
        }
        EventKind::RealmActorManagerChange => {
            let original: RealmActorManagerChangePayload = decode(json!(binding_event.payload))?;
            if binding_event.actor_id != *actor || original.new_service_id != manager.service_id {
                return Err(invalid("previous manager handover differs"));
            }
            (
                original.next_resolution,
                binding_event
                    .producer_proof
                    .as_ref()
                    .ok_or_else(|| invalid("manager binding signature absent"))?
                    .verification_method
                    .clone(),
            )
        }
        _ => return Err(invalid("manager binding writer is not registered")),
    };
    let binding_control = RealmActorControlValue {
        resolution: arkret_models_identity::PrincipalResolutionProjection {
            did: resolution.did,
            method_history_head: resolution.method_history_head,
            version_id: resolution.version_id,
            resolution_event_ref: binding_event.event_id.to_string(),
            updated_at: binding_event.created_at,
        },
        control_method_kid: method,
    };
    let registration = crate::managed_message_actor::registration(conn, event).await?;
    if registration.service_id != payload.new_service_id
        || registration.webhook_auth.key_ref != payload.new_service_signature.verification_method
        || !registration.namespaces.actors.iter().any(|namespace| {
            namespace_pattern_matches(
                AppletNamespaceDomain::Actors,
                &namespace.pattern,
                payload.next_resolution.did.as_str(),
            )
        })
    {
        return Err(invalid(
            "receiving Service registration or retained DID namespace differs",
        ));
    }
    registration
        .manifest
        .registration_epoch_evidence
        .validate_against_did_document(&service.service_did_document)
        .map_err(invalid)?;
    #[derive(QueryableByName)]
    struct Row {
        #[diesel(sql_type=Jsonb)]
        value: Value,
    }
    let registered = sql_query("SELECT to_jsonb(a) AS value FROM applet_registration_current_results r JOIN applet_registration_instances a ON a.realm_id=r.realm_id AND a.applet_id=r.applet_id AND a.instance_event_ref=r.instance_event_ref WHERE r.realm_id=$1 AND r.applet_id=$2 AND a.registration_event_ref=$3")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(registration.applet_id.as_str())
        .bind::<Text,_>(payload.new_registration_ref.as_str()).get_result::<Row>(&mut *conn).await?;
    if registered.value.is_null() {
        return Err(invalid("receiving registration is unavailable"));
    }
    arkret_identity::verify_realm_actor_manager_successor(
        actor,
        &registration.applet_id,
        &binding_control,
        &control.value,
        &control
            .current_event
            .producer_proof
            .as_ref()
            .ok_or_else(|| invalid("accepted control update original signature absent"))?
            .verification_method,
        &payload,
        &service.service_did_document,
        commit.committed_at,
    )
    .map_err(invalid)?;
    crate::realm_authorization_cut::RealmAuthorizationCut::require_realm_actor_manager_change(
        conn, event, commit, prepared, &payload,
    )
    .await?;
    let accepted = CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };
    crate::realm_actor_recovery::inventory(conn, actor, payload.expected_generation, &accepted)
        .await?;
    // The owner remains paused, governance remains unchanged, and the current
    // recovery permission survives. No new Device or business grant is created.
    Ok(vec![
        (
            manager_selector,
            json!(RealmActorManagerValue {
                service_id: payload.new_service_id,
                registration_ref: payload.new_registration_ref,
                binding_ref: accepted,
            }),
        ),
        (
            json!({"kind":"realm_actor_control","actor_id":actor}),
            json!(RealmActorControlValue {
                resolution: arkret_models_identity::PrincipalResolutionProjection {
                    did: payload.next_resolution.did,
                    method_history_head: payload.next_resolution.method_history_head,
                    version_id: payload.next_resolution.version_id,
                    resolution_event_ref: event.event_id.to_string(),
                    updated_at: event.created_at,
                },
                control_method_kid: control.value.control_method_kid,
            }),
        ),
        (
            generation_selector,
            json!(RealmActorDeviceGenerationValue {
                current_device_generation_ref: payload.new_generation,
            }),
        ),
    ])
}
