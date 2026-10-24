//! Current projections of an already verified and committed Applet domain unit.
//! The specialized authoring admission owns service proofs and closed-unit guards.

use arkret_models_integration::AppletRegistrationPayload;
use arkret_wire::{Event, EventKind, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};

// Both operands have already been decoded as the closed SDK registration
// payload. Its controller proof authenticates a snapshot but is not a security
// binding in the registration epoch transcript. Re-proving that snapshot does
// not rotate the accepted instance; every other member remains exact.
pub(crate) fn registration_security_value(value: &serde_json::Value) -> serde_json::Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("proof");
        object.remove("expected_revision");
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
            #[diesel(sql_type = Text)]
            current_commit_id: String,
            #[diesel(sql_type = BigInt)]
            current_stream_position: i64,
        }
        let prior = sql_query("SELECT value,instance_event_ref,current_commit_id,current_stream_position FROM applet_registration_current_states WHERE realm_id=$1 AND applet_id=$2 AND service_id=$3 FOR UPDATE")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.applet_id.as_str())
            .bind::<Text,_>(payload.service_id.as_str())
            .get_result::<PriorRegistration>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let actual_revision = prior
            .as_ref()
            .map(|prior| -> PersistenceResult<arkret_wire::CurrentRevision> {
                Ok(arkret_wire::CurrentRevision {
                    commit_id: prior
                        .current_commit_id
                        .parse()
                        .map_err(PersistenceError::database)?,
                    stream_position: u64::try_from(prior.current_stream_position)
                        .map_err(PersistenceError::database)?,
                })
            })
            .transpose()?;
        if payload.expected_revision != actual_revision {
            return Err(PersistenceError::Conflict(
                "cas_conflict: Applet registration revision changed".into(),
            ));
        }
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
        sql_query("INSERT INTO applet_registration_current_states (realm_id,applet_id,instance_event_ref,current_commit_id,current_stream_position,value,updated_at,service_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (realm_id,applet_id,service_id) DO UPDATE SET instance_event_ref=EXCLUDED.instance_event_ref,current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.applet_id.as_str())
            .bind::<Text,_>(&instance).bind::<Text,_>(commit.commit_id.as_str())
            .bind::<BigInt,_>(i64::try_from(commit.stream_position).map_err(PersistenceError::database)?)
            .bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(commit.committed_at).bind::<Text,_>(payload.service_id.as_str())
            .execute(conn).await.map_err(PersistenceError::database)?;
        return Ok(());
    }
    Ok(())
}

/// Freeze a Service parent's real registration at the grant acceptance cut.
/// This applies equally to install grants and separately issued business parents.
pub(crate) async fn retain_service_grant_source(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::governance::grant_constraint::{
        CapabilitySubject, GrantConstraintKind, GrantConstraintSubkind,
    };
    let CapabilitySubject::Actor(arkret_wire::ActorId::Service { service_id }) = &grant.subject
    else {
        return Ok(());
    };
    let bindings: Vec<_> = grant
        .constraints
        .iter()
        .filter(|constraint| {
            constraint.constraint_kind == GrantConstraintKind::AuthorityControl
                && constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority)
        })
        .collect();
    if bindings.is_empty() {
        return Ok(());
    }
    let [binding] = bindings.as_slice() else {
        return Err(PersistenceError::SchemaViolation(
            "Service grant needs one Applet binding".into(),
        ));
    };
    let applet = binding.applet_id.as_ref().ok_or_else(|| {
        PersistenceError::SchemaViolation("Applet binding lacks its Applet".into())
    })?;
    let epoch = binding.registration_epoch.as_ref().ok_or_else(|| {
        PersistenceError::SchemaViolation("Applet binding lacks its epoch".into())
    })?;
    if binding.executed_by.as_ref() != Some(&arkret_wire::ActorId::service(service_id.clone())) {
        return Err(PersistenceError::SchemaViolation(
            "Applet binding differs from the Service subject".into(),
        ));
    }
    let count = sql_query("INSERT INTO applet_grant_registration_sources (realm_id,grant_id,applet_id,service_id,registration_event_ref) SELECT r.realm_id,$2,r.applet_id,r.service_id,c.commit_json->>'event_ref' FROM applet_registration_current_states r JOIN realm_commits c ON c.commit_id=r.current_commit_id WHERE r.realm_id=$1 AND r.applet_id=$3 AND r.service_id=$4 AND r.value->>'registration_epoch'=$5")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(grant.id.as_str())
        .bind::<Text,_>(applet.as_str()).bind::<Text,_>(service_id.as_str()).bind::<Text,_>(epoch.as_str())
        .execute(conn).await.map_err(PersistenceError::database)?;
    if count != 1 {
        return Err(PersistenceError::Conflict(
            "failed_precondition: Service grant registration source is unavailable".into(),
        ));
    }
    Ok(())
}
