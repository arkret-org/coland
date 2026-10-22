//! Realm-owned Applet control state, committed with the original Event.
use arkret_models_integration::RealmActorCreatePayload;
use arkret_wire::{ActorId, Event, EventKind, RealmCommit, ScopeRef, TypedCurrentRow};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Binary, Jsonb, Nullable, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

fn denied(message: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {message}"))
}

/// Serialize routing authority with the accepted control state, including replay.
pub(crate) async fn require_current_governor(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    governor: &arkret_wire::DidCoreId,
) -> PersistenceResult<()> {
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, realm).await?;
    #[derive(QueryableByName)]
    struct Authority {
        #[diesel(sql_type = Text)]
        service_id: String,
    }
    let authority = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .get_result::<Authority>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    if authority.service_id != governor.as_str() {
        return Err(PersistenceError::Conflict(
            "stale_realm_authority: destination is not the current Realm governor".into(),
        ));
    }
    Ok(())
}

pub(crate) fn creation(event: &Event) -> PersistenceResult<Option<RealmActorCreatePayload>> {
    if event.kind != EventKind::RealmActorCreate {
        return Ok(None);
    }
    let candidate: RealmActorCreatePayload =
        serde_json::from_value(json!(event.payload)).map_err(denied)?;
    candidate.validate().map_err(denied)?;
    let actor = candidate
        .actor_id
        .as_realm_actor_id()
        .ok_or_else(|| denied("creation subject is not Realm-owned"))?;
    if event.realm_id != actor.realm_id
        || event.scope_ref
            != (ScopeRef::RealmControl {
                realm_id: actor.realm_id.clone(),
            })
        || event.actor_id != ActorId::service(candidate.service_id.clone())
        || event.applet_id.as_ref() != Some(&candidate.applet_id)
        || event.authorization_ref.as_deref() != Some(candidate.creation_authorization_ref.as_str())
        || event.executed_by.is_some()
    {
        return Err(denied(
            "creation envelope does not bind the exact candidate",
        ));
    }
    Ok(Some(candidate))
}

pub(crate) fn effective_scope(event: &Event) -> PersistenceResult<ScopeRef> {
    Ok(creation(event)?.map_or_else(
        || event.scope_ref.clone(),
        |candidate| candidate.creation_scope,
    ))
}

pub(crate) async fn creation_source(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
) -> PersistenceResult<RealmActorCreatePayload> {
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| denied("Realm actor required"))?;
    let row=sql_query("SELECT e.envelope AS value FROM realm_actor_creations r JOIN realm_commits c ON c.commit_id=r.commit_id AND c.realm_id=r.realm_id JOIN canonical_events e ON e.pk=c.event_pk WHERE r.realm_id=$1 AND r.actor_id=$2 AND e.state='committed' AND e.kind='ak.realm.actor.create'")
        .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(actor)).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||denied("Realm identity has no accepted creation original"))?;
    let event: Event = serde_json::from_value(row.value).map_err(denied)?;
    let candidate =
        creation(&event)?.ok_or_else(|| denied("identity original is not a creation"))?;
    if &candidate.actor_id != actor {
        return Err(denied("identity original names another complete Actor"));
    }
    Ok(candidate)
}

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

/// Read an accepted current and its original writer, never manufacture a source from a head.
pub(crate) async fn current_source(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    selector: Value,
) -> PersistenceResult<(Value, arkret_wire::CommittedEventRef)> {
    optional_current_source(conn, actor, selector)
        .await?
        .ok_or_else(|| denied("accepted Realm control current is unavailable"))
}

/// Absence is meaningful only for an optional, never-written selector. Callers
/// serialize writes with the parent Realm lock or read one repeatable-read cut.
pub(crate) async fn optional_current_source(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    selector: Value,
) -> PersistenceResult<Option<(Value, arkret_wire::CommittedEventRef)>> {
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| denied("Realm actor required"))?;
    let selector: arkret_wire::CurrentSelector =
        serde_json::from_value(selector).map_err(denied)?;
    if arkret_models_integration::realm_actor_selector_subject(&selector) != Some(actor) {
        return Err(denied(
            "private current selector names another complete actor",
        ));
    }
    let Some(row) = sql_query("SELECT jsonb_build_object('value',r.value,'event',e.envelope,'commit',c.commit_json) AS value FROM realm_actor_current_results r LEFT JOIN realm_commits c ON c.commit_id=r.current_commit_id AND c.stream_position=r.current_stream_position AND c.stream_ref=r.source_stream_ref AND c.realm_id=r.realm_id LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE r.realm_id=$1 AND r.actor_id=$2 AND r.selector=$3")
        .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(actor)).bind::<Jsonb,_>(json!(selector))
        .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)? else { return Ok(None); };
    let event: Event = serde_json::from_value(row.value["event"].clone()).map_err(denied)?;
    let commit: RealmCommit =
        serde_json::from_value(row.value["commit"].clone()).map_err(denied)?;
    arkret_wire::CommittedEventFullView {
        event,
        commit: commit.clone(),
    }
    .validate_shape()
    .map_err(denied)?;
    if commit.stream_ref
        != (arkret_wire::CommitStreamRef::RealmControl {
            realm_id: subject.realm_id.clone(),
        })
    {
        return Err(denied(
            "current writer is outside the subject's private control stream",
        ));
    }
    Ok(Some((
        row.value["value"].clone(),
        arkret_wire::CommittedEventRef {
            event_id: commit.event_ref,
            commit_id: commit.commit_id,
            stream_ref: commit.stream_ref,
            stream_position: commit.stream_position,
        },
    )))
}

/// Prepare only the immutable signer evidence. The control unit must separately
/// verify native recovery, all CAS predicates and atomic fence/current effects.
pub(crate) async fn recovery_service_fact(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &coland_storage::AppletEventProducerGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact>
{
    use arkret_models_collaboration::authority_commit::{
        HistoricalProducerSignerFact, RealmRecoveryServiceHistoricalSignerFact,
        RealmRecoveryServiceHistoricalSignerFactKind,
    };
    let target: ActorId = match event.kind {
        EventKind::RealmActorRecoveryBegin => {
            serde_json::from_value::<arkret_models_integration::RealmActorRecoveryBeginPayload>(
                json!(event.payload),
            )
            .map_err(denied)?
            .target_actor_id
        }
        EventKind::RealmActorControlReset => {
            serde_json::from_value::<arkret_models_integration::RealmActorControlResetPayload>(
                json!(event.payload),
            )
            .map_err(denied)?
            .target_actor_id
        }
        _ => return Err(denied("recovery signer fact requires a recovery Event")),
    };
    let registration = crate::managed_message_actor::registration(conn, event).await?;
    if event.actor_id != ActorId::service(registration.service_id.clone())
        || event.executed_by.is_some()
    {
        return Err(denied(
            "recovery must be signed by the registered Service itself",
        ));
    }
    registration
        .manifest
        .registration_epoch_evidence
        .validate_against_did_document(&guard.service_did_document)
        .map_err(denied)?;
    let (manager, manager_ref) = current_source(
        conn,
        &target,
        json!({"kind":"realm_actor_manager","actor_id":target}),
    )
    .await?;
    let (recovery, recovery_ref) = current_source(
        conn,
        &target,
        json!({"kind":"realm_actor_recovery","actor_id":target}),
    )
    .await?;
    if manager["service_id"] != json!(registration.service_id)
        || recovery["enabled"] != true
        || recovery["kind"] != "manager_native"
    {
        return Err(denied(
            "Service no longer holds enabled native recovery authority",
        ));
    }
    let identity=sql_query("SELECT to_jsonb(c) AS value FROM realm_actor_creations c WHERE realm_id=$1 AND actor_id=$2 AND applet_id=$3")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(target)).bind::<Text,_>(registration.applet_id.as_str())
        .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if identity.is_none() {
        return Err(denied(
            "recovery Applet does not own the target Realm identity",
        ));
    }
    let registered=sql_query("SELECT c.commit_json AS value FROM applet_registration_current_results r JOIN applet_registration_instances a ON a.realm_id=r.realm_id AND a.applet_id=r.applet_id AND a.instance_event_ref=r.instance_event_ref JOIN realm_commits c ON c.commit_id=a.accepted_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE r.realm_id=$1 AND r.applet_id=$2 AND r.service_id=$3 AND e.state='committed'")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(registration.applet_id.as_str()).bind::<Text,_>(registration.service_id.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let registration_commit: RealmCommit =
        serde_json::from_value(registered.value).map_err(denied)?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| denied("recovery Service producer proof is absent"))?;
    if proof.verification_method != registration.webhook_auth.key_ref {
        return Err(denied("recovery method differs from current registration"));
    }
    arkret_identity::validate_verification_method_relationship(
        &guard.service_did_document,
        &proof.verification_method,
        &guard.service_did_document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(denied)?;
    let key = arkret_identity::public_key_material_from_document(
        &guard.service_did_document,
        &proof.verification_method,
    )
    .map_err(denied)?;
    let fact = HistoricalProducerSignerFact::RealmRecoveryService(
        RealmRecoveryServiceHistoricalSignerFact {
            kind: RealmRecoveryServiceHistoricalSignerFactKind::RealmRecoveryService,
            event_id: event.event_id.clone(),
            actor_id: event.actor_id.clone(),
            target_actor_id: target,
            verification_method: proof.verification_method.clone(),
            public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                key.ed25519_bytes().map_err(denied)?,
            ))
            .map_err(denied)?,
            accepted_at: arkret_canonical::normalize_timestamp_canonical(at),
            applet_id: registration.applet_id,
            registration_epoch: registration.registration_epoch,
            registration_ref: arkret_wire::CommittedEventRef {
                event_id: registration_commit.event_ref,
                commit_id: registration_commit.commit_id,
                stream_ref: registration_commit.stream_ref,
                stream_position: registration_commit.stream_position,
            },
            manager_ref,
            recovery_ref,
        },
    );
    arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
        event,
        &fact,
        event.realm_id.digest_suite_code().digest_suite(),
    )
    .map_err(denied)?;
    Ok(fact)
}

/// Runs under the Realm authority lock before any accepting write.
pub(crate) async fn admit_creation(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    let Some(candidate) = creation(event)? else {
        return Ok(());
    };
    arkret_identity::verify_realm_actor_initial_resolution(&candidate, commit.committed_at)
        .map_err(denied)?;
    let genesis = sql_query("SELECT e.envelope->'payload'->'object' AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.realm_id=$1 AND e.kind='ak.realm.create' AND e.state='committed' ORDER BY c.stream_position LIMIT 1")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| denied("creation requires the accepted collaboration Realm genesis"))?;
    if genesis.value.get("purpose").and_then(Value::as_str) != Some("collaboration") {
        return Err(denied(
            "managed actors require an ordinary collaboration Realm",
        ));
    }
    let registration = crate::managed_message_actor::registration(conn, event).await?;
    if registration.service_id != candidate.service_id
        || candidate.actor_id.signing_principal_id() == &registration.controller_principal_id
    {
        return Err(denied("creation manager differs from active registration"));
    }
    let registered = sql_query("SELECT to_jsonb(a) AS value FROM applet_registration_current_results r JOIN applet_registration_instances a ON a.realm_id=r.realm_id AND a.applet_id=r.applet_id AND a.instance_event_ref=r.instance_event_ref WHERE r.realm_id=$1 AND r.applet_id=$2 AND a.registration_event_ref=$3")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(candidate.applet_id.as_str()).bind::<Text,_>(candidate.registration_ref.as_str())
        .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if registered.is_none() {
        return Err(denied(
            "creation registration instance is no longer current",
        ));
    }
    // The parent Realm lock serializes the empty-stream case and all uniqueness keys.
    let occupied = sql_query("SELECT to_jsonb(c) AS value FROM realm_actor_creations c WHERE realm_id=$1 AND (actor_id=$2 OR (applet_id=$3 AND request_id=$4) OR ($5::jsonb IS NOT NULL AND applet_id=$3 AND external_ref=$5)) LIMIT 1")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(candidate.actor_id))
        .bind::<Text,_>(candidate.applet_id.as_str()).bind::<Text,_>(&candidate.request_id)
        .bind::<Nullable<Jsonb>,_>(candidate.external_ref.as_ref().map(|value| json!(value)))
        .get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if occupied.is_some() {
        return Err(denied(
            "Realm actor identity, request or external mapping is already occupied",
        ));
    }
    Ok(())
}

/// The caller has inserted the real Event and Commit in this same transaction.
pub(crate) async fn commit_creation(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    let Some(candidate) = creation(event)? else {
        return Ok(());
    };
    let rows = arkret_models_integration::realm_actor_creation_current_rows(event, commit)
        .map_err(denied)?;
    sql_query("INSERT INTO realm_actor_creations(realm_id,actor_id,applet_id,request_id,candidate_bytes,external_ref,event_id,commit_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(candidate.actor_id))
        .bind::<Text,_>(candidate.applet_id.as_str()).bind::<Text,_>(&candidate.request_id)
        .bind::<Binary,_>(arkret_canonical::canonical_json_bytes(&candidate).map_err(denied)?)
        .bind::<Nullable<Jsonb>,_>(candidate.external_ref.as_ref().map(|value| json!(value)))
        .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(commit.commit_id.as_str())
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    for TypedCurrentRow::Value {
        selector,
        source_stream_ref,
        revision,
        value,
    } in rows
    {
        sql_query("INSERT INTO realm_actor_current_results(realm_id,actor_id,selector,source_stream_ref,current_commit_id,current_stream_position,value) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(candidate.actor_id))
            .bind::<Jsonb,_>(json!(selector)).bind::<Jsonb,_>(json!(source_stream_ref))
            .bind::<Text,_>(revision.commit_id.as_str()).bind::<BigInt,_>(i64::try_from(revision.stream_position).map_err(denied)?)
            .bind::<Jsonb,_>(value).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    }
    Ok(())
}

/// Project one registered writer only after its Event and Commit exist in the
/// same locked transaction. The protocol value is derived by the owning unit.
pub(crate) async fn write_current(
    conn: &mut AsyncPgConnection,
    actor: &ActorId,
    selector: Value,
    value: Value,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    let selector: arkret_wire::CurrentSelector =
        serde_json::from_value(selector).map_err(denied)?;
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| denied("Realm actor required"))?;
    if arkret_models_integration::realm_actor_selector_subject(&selector) != Some(actor)
        || commit.realm_id != subject.realm_id
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::RealmControl {
                realm_id: subject.realm_id.clone(),
            })
    {
        return Err(denied("private current writer identity or stream differs"));
    }
    let written=sql_query("INSERT INTO realm_actor_current_results(realm_id,actor_id,selector,source_stream_ref,current_commit_id,current_stream_position,value) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(realm_id,selector) DO UPDATE SET source_stream_ref=EXCLUDED.source_stream_ref,current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value WHERE realm_actor_current_results.actor_id=EXCLUDED.actor_id AND realm_actor_current_results.source_stream_ref=EXCLUDED.source_stream_ref AND realm_actor_current_results.current_stream_position<EXCLUDED.current_stream_position")
        .bind::<Text,_>(subject.realm_id.as_str()).bind::<Jsonb,_>(json!(actor)).bind::<Jsonb,_>(json!(selector))
        .bind::<Jsonb,_>(json!(commit.stream_ref)).bind::<Text,_>(commit.commit_id.as_str())
        .bind::<BigInt,_>(i64::try_from(commit.stream_position).map_err(denied)?).bind::<Jsonb,_>(value)
        .execute(conn).await.map_err(PersistenceError::database)?;
    if written != 1 {
        return Err(denied(
            "private current writer did not advance its accepted source",
        ));
    }
    Ok(())
}
