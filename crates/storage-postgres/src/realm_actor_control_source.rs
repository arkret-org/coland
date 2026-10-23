//! Exact accepted Realm control source and original control signatures.
use arkret_models_collaboration::authority_commit::{
    HistoricalProducerSignerFact, RealmControlHistoricalSignerFact,
    RealmControlHistoricalSignerFactKind,
};
use arkret_models_identity::PrincipalResolutionProjection;
use arkret_models_integration::{
    RealmActorControlResetPayload, RealmActorControlUpdatePayload, RealmActorControlValue,
    RealmActorCreatePayload, RealmActorManagerChangePayload, RealmActorRecoveryBeginPayload,
};
use arkret_wire::{ActorId, CommittedEventRef, Event, EventKind, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use horme::RunQueryDsl;
use serde_json::{Value, json};

fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {error}"))
}
#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
pub(crate) struct AcceptedControl {
    pub value: RealmActorControlValue,
    pub source: CommittedEventRef,
    pub current_event: Event,
}

pub(crate) async fn original(
    conn: &mut AsyncPgConnection,
    source: &CommittedEventRef,
) -> PersistenceResult<(Event, RealmCommit)> {
    let row = sql_query("SELECT jsonb_build_object('event',e.envelope,'commit',c.commit_json) AS value FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1 AND e.state='committed'")
        .bind::<Text,_>(source.commit_id.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let event: Event = serde_json::from_value(row.value["event"].clone()).map_err(invalid)?;
    let commit: RealmCommit =
        serde_json::from_value(row.value["commit"].clone()).map_err(invalid)?;
    arkret_wire::CommittedEventFullView {
        event: event.clone(),
        commit: commit.clone(),
    }
    .validate_shape()
    .map_err(invalid)?;
    if source.event_id != event.event_id
        || source.stream_ref != commit.stream_ref
        || source.stream_position != commit.stream_position
    {
        return Err(invalid(
            "private current writer does not match its full source coordinate",
        ));
    }
    // This also checks the immutable fact digest and the original producer's
    // cryptographic signature. Historical acceptance never reauthorizes today.
    if crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
        conn, &event, &commit,
    )
    .await?
    .is_none()
    {
        return Err(invalid(
            "private current writer has no retained original signing fact",
        ));
    }
    Ok((event, commit))
}

pub(crate) async fn current(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
) -> PersistenceResult<AcceptedControl> {
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| invalid("Realm actor required"))?;
    let (value, source) = crate::realm_actor_control::current_source(
        conn,
        actor,
        json!({"kind":"realm_actor_control","actor_id":actor}),
    )
    .await?;
    let value: RealmActorControlValue = serde_json::from_value(value).map_err(invalid)?;
    let (event, _) = original(conn, &source).await?;
    let (resolution, method) = match event.kind {
        EventKind::RealmActorCreate => {
            let payload: RealmActorCreatePayload =
                serde_json::from_value(json!(event.payload)).map_err(invalid)?;
            if payload.actor_id != *actor {
                return Err(invalid("control creation belongs to another actor"));
            }
            (payload.initial_resolution, payload.control_method_kid)
        }
        EventKind::RealmActorControlUpdate => {
            if event.actor_id != *actor {
                return Err(invalid("control update belongs to another actor"));
            }
            let payload: RealmActorControlUpdatePayload =
                serde_json::from_value(json!(event.payload)).map_err(invalid)?;
            (payload.next_resolution, payload.next_control_method_kid)
        }
        EventKind::RealmActorManagerChange => {
            if event.actor_id != *actor {
                return Err(invalid("manager change belongs to another actor"));
            }
            let payload: RealmActorManagerChangePayload =
                serde_json::from_value(json!(event.payload)).map_err(invalid)?;
            let method = event
                .producer_proof
                .as_ref()
                .ok_or_else(|| invalid("manager change proof absent"))?
                .verification_method
                .clone();
            (payload.next_resolution, method)
        }
        EventKind::RealmActorControlReset => {
            let payload: RealmActorControlResetPayload =
                serde_json::from_value(json!(event.payload)).map_err(invalid)?;
            if payload.target_actor_id != *actor {
                return Err(invalid("control reset belongs to another actor"));
            }
            let (begin, _) = original(conn, &payload.recovery_begin_ref).await?;
            let intent: RealmActorRecoveryBeginPayload =
                serde_json::from_value(json!(begin.payload)).map_err(invalid)?;
            if begin.kind != EventKind::RealmActorRecoveryBegin
                || intent.target_actor_id != *actor
                || begin.realm_id != subject.realm_id
            {
                return Err(invalid(
                    "control reset has no exact accepted recovery target",
                ));
            }
            (intent.next_resolution, intent.next_control_method_kid)
        }
        _ => return Err(invalid("unregistered Realm control writer")),
    };
    let expected = RealmActorControlValue {
        resolution: PrincipalResolutionProjection {
            did: resolution.did,
            method_history_head: resolution.method_history_head,
            version_id: resolution.version_id,
            resolution_event_ref: event.event_id.to_string(),
            updated_at: event.created_at,
        },
        control_method_kid: method,
    };
    if value != expected || event.realm_id != subject.realm_id {
        return Err(invalid(
            "Realm control current differs from its original writer",
        ));
    }
    Ok(AcceptedControl {
        value,
        source,
        current_event: event,
    })
}

pub(crate) fn native_evidence(
    control: &AcceptedControl,
) -> PersistenceResult<arkret_models_integration::AppletManagedActorMethodHistoryEvidence> {
    let event = &control.current_event;
    let field = match event.kind {
        EventKind::RealmActorCreate
        | EventKind::RealmActorControlUpdate
        | EventKind::RealmActorManagerChange => "method_history_evidence",
        EventKind::RealmActorControlReset => "published_method_history_evidence",
        _ => return Err(invalid("control writer has no native evidence carrier")),
    };
    let evidence: arkret_models_integration::AppletManagedActorMethodHistoryEvidence =
        serde_json::from_value(
            event
                .payload
                .get(field)
                .cloned()
                .ok_or_else(|| invalid("accepted control writer has no retained native history"))?,
        )
        .map_err(invalid)?;
    evidence.validate_shape().map_err(invalid)?;
    Ok(evidence)
}

/// The accepted control writer retains the native evidence for this exact key.
/// A later published DID head must not replace an unaccepted Realm control cut.
pub(crate) async fn document(
    _conn: &mut AsyncPgConnection,
    actor: &ActorId,
    control: &AcceptedControl,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<arkret_identity::DidDocument> {
    let projection = &control.value.resolution;
    let evidence = native_evidence(control)?;
    let (receipt, log_entries, witness_records) = evidence.webvh_material();
    let resolution = arkret_models_identity::ResolutionCommitment {
        did: projection.did.clone(),
        version_id: projection.version_id.clone(),
        method_history_head: projection.method_history_head.clone(),
    };
    if evidence.boundary().to_version_id != resolution.version_id
        || evidence.boundary().to_method_history_head != resolution.method_history_head
    {
        return Err(invalid(
            "accepted native evidence terminal differs from current control",
        ));
    }
    let document = arkret_identity::verify_realm_actor_native_history(
        actor,
        &resolution,
        log_entries,
        &control.value.control_method_kid,
        at,
    )
    .map_err(invalid)?;
    let mut bytes = Vec::new();
    for entry in log_entries {
        bytes.extend(arkret_canonical::canonical_json_bytes(entry).map_err(invalid)?);
        bytes.push(b'\n');
    }
    let witnesses = arkret_canonical::canonical_json_bytes(witness_records).map_err(invalid)?;
    arkret_identity::verify_did_webvh_v1_chain_and_witness_bytes(
        &projection.did,
        &bytes,
        Some(&witnesses),
    )
    .map_err(invalid)?;
    if receipt.document_digest
        != arkret_models_identity::normalized_did_document_digest(&document).map_err(invalid)?
    {
        return Err(invalid(
            "native evidence digest differs from verified control document",
        ));
    }
    Ok(document)
}

pub(crate) async fn signer_fact(
    conn: &mut AsyncPgConnection,
    event: &Event,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<HistoricalProducerSignerFact> {
    let control = current(conn, &event.actor_id).await?;
    let document = document(conn, &event.actor_id, &control, at).await?;
    let method = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| invalid("Realm control producer proof absent"))?
        .verification_method
        .clone();
    if method != control.value.control_method_kid {
        return Err(invalid("producer is not the accepted control method"));
    }
    let key =
        arkret_identity::public_key_material_from_document(&document, &method).map_err(invalid)?;
    let fact = HistoricalProducerSignerFact::RealmControl(RealmControlHistoricalSignerFact {
        kind: RealmControlHistoricalSignerFactKind::RealmControl,
        event_id: event.event_id.clone(),
        actor_id: event.actor_id.clone(),
        verification_method: method,
        public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            key.ed25519_bytes().map_err(invalid)?,
        ))
        .map_err(invalid)?,
        accepted_at: arkret_canonical::normalize_timestamp_canonical(at),
        control_event_ref: control.source,
    });
    arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
        event,
        &fact,
        event.realm_id.digest_suite_code().digest_suite(),
    )
    .map_err(invalid)?;
    Ok(fact)
}
