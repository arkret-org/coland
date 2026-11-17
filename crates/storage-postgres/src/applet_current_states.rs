//! Current projections of an already verified and committed Applet domain unit.
//! The specialized authoring admission owns service proofs and closed-unit guards.

mod source;
use arkret_models_integration::AppletRegistrationPayload;
use arkret_wire::{Event, EventKind, RealmCommit};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
pub(crate) use source::finite_source_for_event;

// Both operands have already been decoded as the closed SDK registration
// payload. Its controller proof authenticates a snapshot but is not a security
// binding in the registration epoch transcript. Re-proving that snapshot does
// not rotate the accepted instance; every other member remains exact.
pub(crate) fn registration_security_value(value: &serde_json::Value) -> serde_json::Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("proof");
        object.remove("expected_commit_id");
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
        }
        let prior = sql_query("SELECT value,instance_event_ref,current_commit_id FROM applet_registration_current_states WHERE realm_id=$1 AND applet_id=$2 AND service_id=$3 FOR UPDATE")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(payload.applet_id.as_str())
            .bind::<Text,_>(payload.service_id.as_str())
            .get_result::<PriorRegistration>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        let actual_revision = prior
            .as_ref()
            .map(|prior| -> PersistenceResult<arkret_wire::RealmCommitId> {
                prior
                    .current_commit_id
                    .parse()
                    .map_err(PersistenceError::database)
            })
            .transpose()?;
        if payload.expected_commit_id != actual_revision {
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

/// The complete Realm/PCR set is held by the accepting caller. Lock the
/// shared identity before its exact installation; a locator is never authority.
pub(crate) async fn lock_installation_records(
    conn: &mut AsyncPgConnection,
    applet: &arkret_wire::AppletId,
    service: &arkret_wire::DidCoreId,
    scope: &arkret_wire::ScopeRef,
    target: &arkret_wire::DidCoreId,
) -> PersistenceResult<(Option<serde_json::Value>, Option<serde_json::Value>)> {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        record: serde_json::Value,
    }
    let identity=sql_query("SELECT record FROM applet_managed_identities WHERE applet_id=$1 AND target_station_id=$2 FOR UPDATE")
        .bind::<Text,_>(applet.as_str()).bind::<Text,_>(target.as_str())
        .get_result::<Row>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let key = coland_storage::applet_effective_scope_key(scope)?;
    let installation=sql_query("SELECT record FROM applet_installations WHERE applet_id=$1 AND effective_scope_key=$2 AND service_id=$3 FOR UPDATE")
        .bind::<Text,_>(applet.as_str()).bind::<Text,_>(key).bind::<Text,_>(service.as_str())
        .get_result::<Row>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if installation
        .as_ref()
        .is_some_and(|row| row.record["target_station_id"].as_str() != Some(target.as_str()))
    {
        return Err(PersistenceError::Conflict(
            "stale_state: Applet installation target changed".into(),
        ));
    }
    Ok((identity.map(|r| r.record), installation.map(|r| r.record)))
}

pub(crate) async fn lock_existing_installation(
    conn: &mut AsyncPgConnection,
    applet: &arkret_wire::AppletId,
    service: &arkret_wire::DidCoreId,
    scope: &arkret_wire::ScopeRef,
) -> PersistenceResult<(serde_json::Value, serde_json::Value)> {
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        record: serde_json::Value,
    }
    let missing = || {
        PersistenceError::Conflict(
            "failed_precondition: Applet exact installation source unavailable".into(),
        )
    };
    let key = coland_storage::applet_effective_scope_key(scope)?;
    let locator=sql_query("SELECT record FROM applet_installations WHERE applet_id=$1 AND effective_scope_key=$2 AND service_id=$3")
        .bind::<Text,_>(applet.as_str()).bind::<Text,_>(key).bind::<Text,_>(service.as_str())
        .get_result::<Row>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(missing)?;
    let target = arkret_wire::DidCoreId::new(
        locator.record["target_station_id"]
            .as_str()
            .ok_or_else(missing)?
            .to_owned(),
    )
    .map_err(PersistenceError::database)?;
    let (identity, installation) =
        lock_installation_records(conn, applet, service, scope, &target).await?;
    let identity = identity.ok_or_else(missing)?;
    let installation = installation.ok_or_else(missing)?;
    if installation != locator.record {
        return Err(PersistenceError::Conflict(
            "stale_state: Applet installation changed while locking".into(),
        ));
    }
    Ok((identity, installation))
}

fn service_parent_binding(
    grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
) -> PersistenceResult<
    Option<(
        &arkret_wire::DidCoreId,
        &arkret_wire::AppletId,
        &arkret_wire::Hash,
    )>,
> {
    use arkret_models_collaboration::governance::grant_constraint::{
        CapabilitySubject, GrantConstraintKind, GrantConstraintSubkind,
    };
    let CapabilitySubject::Actor(arkret_wire::ActorId::Service { service_id }) = &grant.subject
    else {
        return Ok(None);
    };
    let bindings = grant
        .constraints
        .iter()
        .filter(|c| {
            c.constraint_kind == GrantConstraintKind::AuthorityControl
                && c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority)
        })
        .collect::<Vec<_>>();
    if bindings.is_empty() {
        return Ok(None);
    }
    let [binding] = bindings.as_slice() else {
        return Err(PersistenceError::SchemaViolation(
            "Service parent needs one Applet binding".into(),
        ));
    };
    let invalid =
        || PersistenceError::SchemaViolation("Service parent has incomplete Applet binding".into());
    let applet = binding.applet_id.as_ref().ok_or_else(invalid)?;
    let epoch = binding.registration_epoch.as_ref().ok_or_else(invalid)?;
    if binding.executed_by.as_ref() != Some(&arkret_wire::ActorId::service(service_id.clone())) {
        return Err(invalid());
    }
    Ok(Some((service_id, applet, epoch)))
}

/// This finite source classifier does not constrain unrelated generic grants.
/// A non-unique/more general resource source remains registration-only and can
/// never be used as this profile's frozen installation source.
pub(super) fn exact_installation_scope(
    realm: &arkret_wire::RealmId,
    grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
) -> Option<arkret_wire::ScopeRef> {
    let mut selected = None;
    for resource in &grant.resources {
        let scope = match resource.kind {
            arkret_wire::ResourceSelectorKind::Realm => {
                arkret_wire::ScopeRef::realm(resource.realm_id.clone()?)
            }
            arkret_wire::ResourceSelectorKind::Circle => arkret_wire::ScopeRef::Circle {
                realm_id: resource.realm_id.clone()?,
                circle_id: resource.circle_id.clone()?,
            },
            _ => return None,
        };
        if scope.realm_id() != realm
            || !resource.is_exact_scope(&scope)
            || selected.as_ref().is_some_and(|old| old != &scope)
        {
            return None;
        }
        selected = Some(scope);
    }
    selected
}

async fn retain_service_source(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    installation_id: Option<&str>,
) -> PersistenceResult<()> {
    let Some((service, applet, epoch)) = service_parent_binding(grant)? else {
        return Ok(());
    };
    if installation_id.is_some_and(str::is_empty) {
        return Err(PersistenceError::SchemaViolation(
            "Applet installation ID is empty".into(),
        ));
    }
    let count=sql_query("INSERT INTO applet_grant_registration_sources (realm_id,grant_id,applet_id,service_id,registration_event_ref,install_id) SELECT r.realm_id,$2,r.applet_id,r.service_id,c.commit_json->>'event_ref',$6 FROM applet_registration_current_states r JOIN realm_commits c ON c.commit_id=r.current_commit_id WHERE r.realm_id=$1 AND r.applet_id=$3 AND r.service_id=$4 AND r.value->>'registration_epoch'=$5")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(grant.id.as_str()).bind::<Text,_>(applet.as_str()).bind::<Text,_>(service.as_str()).bind::<Text,_>(epoch.as_str()).bind::<diesel::sql_types::Nullable<Text>,_>(installation_id)
        .execute(conn).await.map_err(PersistenceError::database)?;
    if count != 1 {
        return Err(PersistenceError::Conflict(
            "failed_precondition: Service parent registration source unavailable".into(),
        ));
    }
    Ok(())
}

/// Preserve generic registration provenance and return its actual installation
/// source. The caller applies any registered first-admission scope requirement;
/// unrelated generic grants may retain registration-only provenance.
pub(crate) async fn retain_service_grant_source(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
) -> PersistenceResult<Option<String>> {
    let installation = current_service_grant_installation(conn, realm, grant).await?;
    retain_service_source(conn, realm, grant, installation.as_deref()).await?;
    Ok(installation)
}

/// Read the exact active installation under the accepting transaction's
/// existing Realm, registration, shared identity and installation locks.
async fn current_service_grant_installation(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
) -> PersistenceResult<Option<String>> {
    let Some((service, applet, epoch)) = service_parent_binding(grant)? else {
        return Ok(None);
    };
    let Some(scope) = exact_installation_scope(realm, grant) else {
        return Ok(None);
    };
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        present: bool,
    }
    let key = coland_storage::applet_effective_scope_key(&scope)?;
    let exists=sql_query("SELECT EXISTS(SELECT 1 FROM applet_installations WHERE applet_id=$1 AND effective_scope_key=$2 AND service_id=$3) AS present")
        .bind::<Text,_>(applet.as_str()).bind::<Text,_>(key).bind::<Text,_>(service.as_str()).get_result::<Row>(&mut *conn).await.map_err(PersistenceError::database)?;
    if !exists.present {
        return Ok(None);
    }
    let (identity, installation) =
        lock_existing_installation(conn, applet, service, &scope).await?;
    if identity
        .get("globally_fenced_at")
        .is_some_and(|v| !v.is_null())
        || installation.get("revoked_at").is_some_and(|v| !v.is_null())
        || !matches!(
            installation["status"].as_str(),
            Some("installed" | "partially_installed")
        )
        || installation
            .pointer("/package/registration_epoch")
            .and_then(serde_json::Value::as_str)
            != Some(epoch.as_str())
    {
        return Ok(None);
    }
    #[derive(diesel::QueryableByName)]
    struct CurrentInstance {
        #[diesel(sql_type=diesel::sql_types::Bool)]
        matches: bool,
    }
    let anchor = installation
        .pointer("/registration_event/event_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            PersistenceError::SchemaViolation("Installation registration is absent".into())
        })?;
    let current=sql_query("SELECT EXISTS(SELECT 1 FROM applet_registration_current_states r JOIN applet_registration_instances a ON a.realm_id=r.realm_id AND a.applet_id=r.applet_id AND a.instance_event_ref=r.instance_event_ref WHERE r.realm_id=$1 AND r.applet_id=$2 AND r.service_id=$3 AND a.registration_event_ref=$4) AS matches")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(applet.as_str()).bind::<Text,_>(service.as_str()).bind::<Text,_>(anchor).get_result::<CurrentInstance>(&mut *conn).await.map_err(PersistenceError::database)?;
    if !current.matches {
        return Ok(None);
    }
    let id = installation["install_id"].as_str().ok_or_else(|| {
        PersistenceError::SchemaViolation("Applet installation ID is absent".into())
    })?;
    Ok(Some(id.to_owned()))
}

/// This nonnullable ID belongs to the same verified installation transaction.
/// Failure in finalization/CAS rolls it back with the original parent/Commit.
pub(crate) async fn retain_installation_grant_source(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    installation_id: &str,
) -> PersistenceResult<()> {
    if service_parent_binding(grant)?.is_none() || exact_installation_scope(realm, grant).is_none()
    {
        return Err(PersistenceError::SchemaViolation(
            "Installation parent has no exact Applet Service source".into(),
        ));
    }
    retain_service_source(conn, realm, grant, Some(installation_id)).await
}
