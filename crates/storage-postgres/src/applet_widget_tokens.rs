//! Host-local widget inventory, serialized with the exact installation fence.
use arkret_models_integration::AppletInstallRequestBody;
use chrono::{DateTime, Utc};
use coland_storage::{
    AppletWidgetInstallSelector, AppletWidgetTokenGateSelector, AppletWidgetTokenInvalidation,
    AppletWidgetTokenRecord, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

#[derive(diesel::QueryableByName)]
struct RecordRow {
    #[diesel(sql_type=Jsonb)]
    record: Value,
}
fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("applet_registration_unauthorized: {detail}"))
}
async fn current_permission(
    conn: &mut AsyncPgConnection,
    install: &AppletWidgetInstallSelector,
    actor: &arkret_wire::ActorId,
    grant_id: &arkret_wire::GrantId,
    actions: &[String],
    resources: &[arkret_wire::WireResourceSelector],
    at: DateTime<Utc>,
) -> PersistenceResult<()> {
    use crate::capability_grant_current_results::{
        CapabilityGrantCurrentResultReadRow, RealmAuthorityRootReadRow, decode_authority_root,
        decode_row, grant_is_active_at, validate_ancestor_graph,
    };
    let current=sql_query("SELECT value AS record FROM applet_registration_current_results WHERE realm_id=$1 AND applet_id=$2 FOR SHARE")
        .bind::<Text,_>(install.effective_scope.realm_id().as_str()).bind::<Text,_>(install.applet_id.as_str())
        .get_result::<RecordRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||denied("widget registration current is absent"))?;
    if current
        .record
        .get("registration_epoch")
        .and_then(Value::as_str)
        != Some(install.registration_epoch.as_str())
    {
        return Err(denied("widget registration epoch is no longer current"));
    }
    let rows=sql_query("SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value FROM capability_grant_current_results WHERE realm_id=$1 ORDER BY grant_id FOR SHARE")
        .bind::<Text,_>(install.effective_scope.realm_id().as_str()).load::<CapabilityGrantCurrentResultReadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut grants = std::collections::BTreeMap::new();
    for row in rows {
        let record = decode_row(row)?;
        grants.insert(record.grant_id, record.value);
    }
    let grant = grants
        .get(grant_id)
        .ok_or_else(|| denied("widget grant has no accepted current"))?;
    if !grant_is_active_at(grant, at)
        || !matches!(&grant.subject,arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(subject) if subject==actor)
    {
        return Err(denied(
            "widget grant is no longer active for its exact actor",
        ));
    }
    let root=sql_query("SELECT realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1")
        .bind::<Text,_>(install.effective_scope.realm_id().as_str()).get_result::<RealmAuthorityRootReadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    validate_ancestor_graph(
        &arkret_wire::GrantId::from_event_id(&install.registration_event_ref),
        grant_id,
        &grants,
        &decode_authority_root(root)?,
        install.effective_scope.realm_id(),
        at,
        &mut std::collections::BTreeSet::new(),
        0,
    )?;
    let facts = coland_storage::OperationFacts {
        applet_id: Some(install.applet_id.to_string()),
        registration_epoch: Some(install.registration_epoch.to_string()),
        ..Default::default()
    };
    for action in actions {
        for target in resources {
            let actions = [action.as_str()];
            let operation = coland_storage::AuthorizationOperation {
                actor,
                actions: &actions,
                target,
                at,
                facts: &facts,
            };
            if coland_storage::evaluate_grants(&operation, std::iter::once(grant))
                .unreserved()
                .is_empty()
            {
                return Err(denied(
                    "widget current grant does not authorize its narrowed scope",
                ));
            }
        }
    }
    Ok(())
}
pub(crate) async fn lock_install(
    conn: &mut AsyncPgConnection,
    install: &AppletWidgetInstallSelector,
    active: bool,
) -> PersistenceResult<Value> {
    let scope = coland_storage::applet_effective_scope_key(&install.effective_scope)?;
    let row=sql_query("SELECT record FROM applet_installations WHERE applet_id=$1 AND effective_scope_key=$2 FOR UPDATE")
        .bind::<Text,_>(install.applet_id.as_str()).bind::<Text,_>(scope)
        .get_result::<RecordRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||denied("widget exact installation is absent"))?;
    if row
        .record
        .pointer("/install_response/registration_event_ref")
        .and_then(Value::as_str)
        != Some(install.registration_event_ref.as_str())
        || row
            .record
            .pointer("/package/registration_epoch")
            .and_then(Value::as_str)
            != Some(install.registration_epoch.as_str())
    {
        return Err(denied("widget exact registration or epoch differs"));
    }
    if active
        && (row.record.get("revoked_at").is_some_and(|v| !v.is_null())
            || !matches!(
                row.record.get("status").and_then(Value::as_str),
                Some("installed" | "partially_installed")
            ))
    {
        return Err(PersistenceError::Conflict(
            "applet_revoked: widget installation is fenced".into(),
        ));
    }
    Ok(row.record)
}
fn pending_revoke(record: &Value) -> bool {
    record
        .get("revoke_execution")
        .filter(|v| !v.is_null())
        .is_some_and(|execution| {
            execution.pointer("/outcome/status").and_then(Value::as_str) != Some("complete")
        })
}
pub(crate) async fn issue(
    conn: &mut AsyncPgConnection,
    record: &AppletWidgetTokenRecord,
) -> PersistenceResult<bool> {
    let current = lock_install(conn, &record.install, true).await?;
    if pending_revoke(&current) || record.invalidated_at.is_some() {
        return Err(denied("widget issuance is fenced by a pending revoke"));
    }
    arkret_models_integration::AppletRevokeLocalEffectRef::new(record.token_ref.clone())
        .map_err(PersistenceError::database)?;
    if !record.token_ref.starts_with("ak:widget_token:") {
        return Err(denied("widget token reference has the wrong kind"));
    }
    // Only an accepted authoring unit can supply the original approval and
    // package declaration. A caller's installation JSON is never an issuer.
    let row=sql_query("SELECT request_body AS record FROM applet_authoring_units WHERE operation_id='ak.self.applet.command.install' AND response_body->>'registration_event_ref'=$1 ORDER BY accepted_at LIMIT 1")
        .bind::<Text,_>(record.install.registration_event_ref.as_str()).get_result::<RecordRow>(&mut *conn)
        .await.optional().map_err(PersistenceError::database)?.ok_or_else(||denied("accepted widget approval is absent"))?;
    let request: AppletInstallRequestBody =
        serde_json::from_value(row.record).map_err(PersistenceError::database)?;
    let basis = &request.authoring_request_basis;
    if basis.effective_scope != record.install.effective_scope
        || basis.applet_id != record.install.applet_id
        || !basis.approval_request.widget_allowed
        || basis
            .widget_policy
            .as_ref()
            .is_some_and(|p| p.widget_allowed == Some(false))
    {
        return Err(denied(
            "widget issuance lacks exact accepted consent policy",
        ));
    }
    let widget = request
        .applet_package
        .widget
        .as_ref()
        .ok_or_else(|| denied("accepted package has no widget declaration"))?;
    if widget.consent_required && !record.consent_approved {
        return Err(denied("widget requires explicit host consent"));
    }
    coland_storage::validate_applet_widget_scope(
        &widget.token_scope,
        &record.token_scope,
        &record.install,
        record.issued_at,
    )?;
    current_permission(
        conn,
        &record.install,
        &record.actor_id,
        &record.authorization_ref,
        &record.token_scope.actions,
        &record.token_scope.resources,
        record.issued_at,
    )
    .await?;
    let scope = coland_storage::applet_effective_scope_key(&record.install.effective_scope)?;
    let value = serde_json::to_value(record).map_err(PersistenceError::database)?;
    let inserted=sql_query("INSERT INTO applet_widget_tokens(token_ref,token_digest,applet_id,effective_scope_key,registration_event_ref,registration_epoch,record,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING")
        .bind::<Text,_>(&record.token_ref).bind::<Text,_>(record.token_digest.as_str()).bind::<Text,_>(record.install.applet_id.as_str())
        .bind::<Text,_>(scope).bind::<Text,_>(record.install.registration_event_ref.as_str()).bind::<Text,_>(record.install.registration_epoch.as_str())
        .bind::<Jsonb,_>(&value).bind::<Timestamptz,_>(record.issued_at).bind::<Timestamptz,_>(record.token_scope.expires_at)
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if inserted == 1 {
        return Ok(true);
    }
    let existing = sql_query("SELECT record FROM applet_widget_tokens WHERE token_ref=$1")
        .bind::<Text, _>(&record.token_ref)
        .get_result::<RecordRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
    if existing.is_some_and(|r| r.record == value) {
        Ok(false)
    } else {
        Err(denied(
            "widget token replay differs from its immutable issuance",
        ))
    }
}
pub(crate) async fn inventory(
    conn: &mut AsyncPgConnection,
    install: &AppletWidgetInstallSelector,
    at: DateTime<Utc>,
) -> PersistenceResult<Vec<AppletWidgetTokenRecord>> {
    lock_install(conn, install, false).await?;
    let scope = coland_storage::applet_effective_scope_key(&install.effective_scope)?;
    sql_query("SELECT record FROM applet_widget_tokens WHERE applet_id=$1 AND effective_scope_key=$2 AND registration_event_ref=$3 AND registration_epoch=$4 AND invalidated_at IS NULL AND expires_at>$5 ORDER BY token_ref")
        .bind::<Text,_>(install.applet_id.as_str()).bind::<Text,_>(scope).bind::<Text,_>(install.registration_event_ref.as_str())
        .bind::<Text,_>(install.registration_epoch.as_str()).bind::<Timestamptz,_>(at)
        .load::<RecordRow>(&mut *conn).await.map_err(PersistenceError::database)?.into_iter()
        .map(|r|serde_json::from_value(r.record).map_err(PersistenceError::database)).collect()
}
pub(crate) async fn check(
    conn: &mut AsyncPgConnection,
    gate: &AppletWidgetTokenGateSelector,
    at: DateTime<Utc>,
) -> PersistenceResult<AppletWidgetTokenRecord> {
    let install = lock_install(conn, &gate.install, true).await?;
    if pending_revoke(&install) {
        return Err(PersistenceError::Conflict(
            "applet_revoked: widget revoke is pending".into(),
        ));
    }
    let row = sql_query("SELECT record FROM applet_widget_tokens WHERE token_digest=$1 FOR SHARE")
        .bind::<Text, _>(gate.token_digest.as_str())
        .get_result::<RecordRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| denied("widget token is absent"))?;
    let record = serde_json::from_value(row.record).map_err(PersistenceError::database)?;
    coland_storage::validate_applet_widget_token_use(&record, gate, at)?;
    current_permission(
        conn,
        &gate.install,
        &gate.actor_id,
        &gate.authorization_ref,
        std::slice::from_ref(&gate.action),
        std::slice::from_ref(&gate.target),
        at,
    )
    .await?;
    Ok(record)
}
pub(crate) async fn check_event(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    gate: &AppletWidgetTokenGateSelector,
    at: DateTime<Utc>,
) -> PersistenceResult<()> {
    use arkret_wire::ResourceSelectorKind;
    gate.target.validate().map_err(PersistenceError::database)?;
    if event.actor_id != gate.actor_id
        || event.authorization_ref.as_ref().map(|id| id.as_str())
            != Some(gate.authorization_ref.as_str())
        || event.scope_ref != gate.install.effective_scope
        || gate.target.realm_id.as_ref() != Some(&event.realm_id)
        || !arkret_schema::capability_actions_for_event_kind(event.kind.as_str()).any(|action| {
            action.action.as_str() == gate.action && action.required_evaluator_checks.is_empty()
        })
    {
        return Err(denied(
            "widget gate does not describe the signed Event action or scope",
        ));
    }
    let target_matches = match gate.target.kind {
        ResourceSelectorKind::Realm => {
            matches!(&event.scope_ref, arkret_wire::ScopeRef::Realm { .. })
        }
        ResourceSelectorKind::Circle => {
            matches!(&event.scope_ref,arkret_wire::ScopeRef::Circle{circle_id,..} if gate.target.circle_id.as_ref()==Some(circle_id))
        }
        ResourceSelectorKind::Strand => gate.target.strand_id.as_ref().is_some_and(|id| {
            event.payload.get("strand_id").and_then(Value::as_str) == Some(id.as_str())
        }),
        ResourceSelectorKind::Message => gate.target.message_id.as_ref().is_some_and(|id| {
            event.payload.get("message_id").and_then(Value::as_str) == Some(id.as_str())
        }),
        _ => false,
    };
    if !target_matches {
        return Err(denied("widget gate target differs from the original Event"));
    }
    check(conn, gate, at).await?;
    Ok(())
}
pub(crate) async fn invalidate(
    conn: &mut AsyncPgConnection,
    install: &AppletWidgetInstallSelector,
    token_ref: &str,
    at: DateTime<Utc>,
) -> PersistenceResult<AppletWidgetTokenInvalidation> {
    lock_install(conn, install, false).await?;
    let row = sql_query("SELECT record FROM applet_widget_tokens WHERE token_ref=$1 FOR UPDATE")
        .bind::<Text, _>(token_ref)
        .get_result::<RecordRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| denied("widget token is absent"))?;
    let mut record: AppletWidgetTokenRecord =
        serde_json::from_value(row.record).map_err(PersistenceError::database)?;
    if &record.install != install {
        return Err(denied("widget invalidation selects another installation"));
    }
    if record.invalidated_at.is_some() {
        return Ok(AppletWidgetTokenInvalidation::AlreadyInvalidated);
    }
    record.invalidated_at = Some(at);
    sql_query("UPDATE applet_widget_tokens SET record=$2,invalidated_at=$3 WHERE token_ref=$1")
        .bind::<Text, _>(token_ref)
        .bind::<Jsonb, _>(serde_json::to_value(record).map_err(PersistenceError::database)?)
        .bind::<Timestamptz, _>(at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    Ok(AppletWidgetTokenInvalidation::Invalidated)
}
