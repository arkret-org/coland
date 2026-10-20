//! Current projections of an already verified and committed Applet domain unit.
//! The specialized authoring admission owns service proofs and closed-unit guards.

use arkret_models_integration::AppletRegistrationPayload;
use arkret_wire::{Event, EventKind, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

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
    Ok(())
}
