//! Current projections of an already verified and committed Applet domain unit.
//! The specialized authoring admission owns service proofs and closed-unit guards.

use arkret_models_integration::{AppletManagedActorProvisionPayload, AppletRegistrationPayload};
use arkret_wire::{CommitStreamRef, Event, EventKind, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

#[derive(diesel::QueryableByName)]
struct SeededResolution {
    #[diesel(sql_type = Text)]
    pcr_realm_id: String,
}

// Both operands have already been decoded as the closed SDK registration
// payload. Its controller proof authenticates a snapshot but is not a security
// binding in the registration epoch transcript. Re-proving that snapshot does
// not rotate the accepted instance; every other member remains exact.
pub(crate) fn registration_security_value(value: &serde_json::Value) -> serde_json::Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("proof");
    }
    value
}

/// Called only after the specialized Applet writer has committed this Event
/// and verified all four producer proofs against the same Service material.
pub(crate) async fn project_applet_event_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    provision: Option<&AppletManagedActorProvisionPayload>,
) -> PersistenceResult<()> {
    if event.kind == EventKind::AppletRegistration {
        let value = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
        let payload: AppletRegistrationPayload =
            serde_json::from_value(value.clone()).map_err(PersistenceError::database)?;
        #[derive(diesel::QueryableByName)]
        struct PriorRegistration {
            #[diesel(sql_type = Jsonb)]
            value: serde_json::Value,
            #[diesel(sql_type = Text)]
            instance_event_ref: String,
        }
        let prior = sql_query("SELECT value,instance_event_ref FROM applet_registration_current_results WHERE realm_id=$1 AND applet_id=$2 FOR UPDATE")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.applet_id.as_str())
            .get_result::<PriorRegistration>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let instance = prior
            .filter(|prior| {
                registration_security_value(&prior.value) == registration_security_value(&value)
            })
            .map(|prior| prior.instance_event_ref)
            .unwrap_or_else(|| event.event_id.to_string());
        sql_query("INSERT INTO applet_registration_instances (realm_id,applet_id,registration_event_ref,instance_event_ref,accepted_commit_id) VALUES ($1,$2,$3,$4,$5)")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.applet_id.as_str())
            .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(&instance)
            .bind::<Text,_>(commit.commit_id.as_str()).execute(&mut *conn).await.map_err(PersistenceError::database)?;
        sql_query("INSERT INTO applet_registration_current_results (realm_id,applet_id,instance_event_ref,current_commit_id,current_stream_position,value,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (realm_id,applet_id) DO UPDATE SET instance_event_ref=EXCLUDED.instance_event_ref,current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.applet_id.as_str())
            .bind::<Text,_>(&instance).bind::<Text,_>(commit.commit_id.as_str())
            .bind::<BigInt,_>(i64::try_from(commit.stream_position).map_err(PersistenceError::database)?)
            .bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(commit.committed_at)
            .execute(conn).await.map_err(PersistenceError::database)?;
        return Ok(());
    }
    if event.kind != EventKind::RealmCreate {
        return Ok(());
    }
    let Some(provision) = provision else {
        return Ok(());
    };
    let account = provision.actor_id.as_account_id().ok_or_else(|| {
        PersistenceError::SchemaViolation("managed PCR requires an exact Account actor".to_owned())
    })?;
    if event.actor_id != provision.actor_id
        || commit.stream_position != 0
        || !matches!(&commit.stream_ref, CommitStreamRef::Realm{realm_id} if realm_id == &event.realm_id)
    {
        return Err(PersistenceError::SchemaViolation(
            "managed PCR projection requires its admitted position-zero genesis".to_owned(),
        ));
    }
    crate::capability_grant_current_results::commit_realm_authority_root_current_result_in_connection(conn,event,commit).await?;
    crate::realm_bootstrap_current_results::commit_ordinary_bootstrap_singleton_current_result_in_connection(conn,event,commit).await?;
    let initial = &provision.initial_resolution;
    let projection = arkret_models_identity::PrincipalResolutionProjection {
        did: initial.did.clone(),
        method_history_head: initial.method_history_head.clone(),
        version_id: initial.version_id.clone(),
        resolution_event_ref: event.event_id.to_string(),
        updated_at: event.created_at,
    };
    let inserted = sql_query(
        "WITH inserted AS ( \
           INSERT INTO principal_resolutions \
             (principal_id,station_id,pcr_realm_id,genesis_event_id,current_event_id,projection,updated_at) \
           VALUES ($1,$2,$3,$4,$4,$5,$6) ON CONFLICT DO NOTHING \
           RETURNING principal_id,station_id \
         ), inserted_event AS ( \
           INSERT INTO principal_resolution_events \
             (principal_id,station_id,event_id,previous_event_id,method_history_head,event_json,created_at) \
           SELECT principal_id,station_id,$4,NULL,$7,$8,$6 FROM inserted \
         ) SELECT $3::text AS pcr_realm_id WHERE EXISTS(SELECT 1 FROM inserted)"
    ).bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(event.event_id.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(&projection).map_err(PersistenceError::database)?)
        .bind::<Timestamptz,_>(projection.updated_at).bind::<Text,_>(&projection.method_history_head)
        .bind::<Jsonb,_>(serde_json::to_value(event).map_err(PersistenceError::database)?)
        .get_result::<SeededResolution>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if inserted
        .as_ref()
        .is_none_or(|row| row.pcr_realm_id != event.realm_id.as_str())
    {
        return Err(PersistenceError::Conflict(
            "failed_precondition: managed account already has a Principal Control Realm".to_owned(),
        ));
    }
    crate::pcr_device_current_results::initialize_managed_pcr_generation_in_connection(
        conn, event, commit,
    )
    .await?;
    Ok(())
}
